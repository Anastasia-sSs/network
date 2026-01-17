package org.example;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;
import org.xbill.DNS.DClass;
import org.xbill.DNS.ResolverConfig;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;


public class Socks5Proxy {
    private static final int TIMEOUT = 5000;
    private static final int SIZE_BUFFER = 512;

    private static Selector selector;
    private static DatagramChannel dnsChannel;
    private static ServerSocketChannel serverChannel;

    private static InetSocketAddress dnsResover = new InetSocketAddress("8.8.8.8", 53);
    private static final Map<Integer, DnsRequestResolve> dnsMap = new HashMap<>();
    private static final Map<SocketChannel, Connection> channelsConnection = new HashMap<>();

    private static final Random rand = new Random();

    private static volatile boolean running = true;

    private static class SocksReplyCodes {
        public static final byte REP_SUCCEEDED = 0x00;
        public static final byte REP_GENERAL_FAILURE = 0x01;
        public static final byte REP_CONNECTION_NOT_ALLOWED = 0x02;
        public static final byte REP_NETWORK_UNREACHABLE = 0x03;
        public static final byte REP_HOST_UNREACHABLE = 0x04;
        public static final byte REP_CONNECTION_REFUSED = 0x05;
        public static final byte REP_TTL_EXPIRED = 0x06;
        public static final byte REP_COMMAND_NOT_SUPPORTED = 0x07;
        public static final byte REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08;
    }

    private static class DnsRequestResolve {
        public final int id;
        public final Connection conn;
        public final String name;
        public final Instant since = Instant.now();

        public DnsRequestResolve(int id, Connection conn, String name) {
            this.id = id;
            this.conn = conn;
            this.name = name;
        }
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("port not specified");
            return;
        }
        int port = Integer.parseInt(args[0]);

        try {
            selector = Selector.open();
            initChannels(port);
            initDnsResolver();
            start();
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                initiateShutdown();
            }));
        }
        catch (IOException e) {
            System.out.println(e.getMessage());
        } finally {
            shutdown();
        }
    }

    private static void initChannels(int port) throws IOException {
        dnsChannel = DatagramChannel.open();
        dnsChannel.configureBlocking(false);
        dnsChannel.bind(null); 
        dnsChannel.register(selector, SelectionKey.OP_READ); //канал имеет данные для чтения
        System.out.println("DNS resolver: " + dnsResover);

        serverChannel = ServerSocketChannel.open();
        serverChannel.configureBlocking(false);
        serverChannel.bind(new InetSocketAddress(port));
        serverChannel.register(selector, SelectionKey.OP_ACCEPT); //сервер готов к подключению
    }

    private static void initDnsResolver() {
        List<InetSocketAddress> servers = ResolverConfig.getCurrentConfig().servers();
        for (InetSocketAddress serv: servers) {
            InetAddress inetAddress = serv.getAddress();
            if (inetAddress instanceof Inet4Address) {
                dnsResover = new InetSocketAddress(inetAddress, serv.getPort() > 0 ? serv.getPort() : 53);
                System.out.println("DNS resolver is taken: " + inetAddress);
                return;
            }
        }
        System.out.println("the default DNS resolver is taken");
    }

    private static void initiateShutdown() {
        running = false;
        if (selector != null && selector.isOpen()) {
            selector.wakeup();
        }
    }

    private static void start() {
        try {
            while (running && selector.isOpen()) {
                selector.select();
                Set<SelectionKey> selectedKeys = selector.selectedKeys();
                if (selectedKeys.isEmpty()) {
                    continue;
                }
                processSelectedKeys(selectedKeys);
                cleanupPendingDns();
            }
        } catch (IOException e) {
            System.err.println("function runEventLoop(): " + e.getMessage());
        }
    }

    private static void processSelectedKeys(Set<SelectionKey> selectedKeys) {
        Iterator<SelectionKey> iter = selectedKeys.iterator();
        while (iter.hasNext()) {
            SelectionKey key = iter.next();
            iter.remove();
            if (!key.isValid()) {
                continue;
            }
            try {
                if (key.isAcceptable()) {
                    handleAccept();
                } else if (key.channel() == dnsChannel && key.isReadable()) {
                    handleDnsResponse();
                } else {
                    if (key.isReadable()) {
                        handleRead(key);
                    }
                    if (key.isConnectable()) {
                        finishConnect(key);
                    }
                    if (key.isWritable()) {
                        handleWrite(key);
                    }
                }
            } catch (IOException e) {
                System.err.println("processSelectedKeys error: " + e.getMessage());
                Connection connection = (Connection) key.attachment();
                if (connection != null) {
                    connection.close();
                    removeConnectionHashMaps(connection);
                }
            }
        }
    }

    private static void handleAccept() throws IOException {
        SocketChannel client = serverChannel.accept();
        if (client == null) {
            return;
        }
        client.configureBlocking(false);
        SelectionKey clientKey = client.register(selector, SelectionKey.OP_READ);
        Connection connection = new Connection();
        connection.client = client;
        clientKey.attach(connection);
        channelsConnection.put(client, connection);
        connection.state = Connection.State.AUTHENITICATION;
    }

    //нам надо как то просигналить если у нас не получилось распарсить dns response
    private static void handleDnsResponse() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(SIZE_BUFFER);
        if (dnsChannel.receive(buffer) == null) {
            return;
        }
        buffer.flip();

        Message response;
        try {
            response = new Message(buffer);
        } catch (IOException e) {
            System.err.println("Failed to parse DNS response: " + e.getMessage());
            return;
        }

        int id = response.getHeader().getID();
        DnsRequestResolve dnsReqRes = dnsMap.remove(id);
        if (dnsReqRes == null) {
            return;
        }

        Connection conn = dnsReqRes.conn;
        if (conn == null || conn.state != Connection.State.RESOLVING) {
            return;
        }

        List<Record> records = response.getSection(Section.ANSWER);
        InetAddress inetAddress = null;
        for (Record rec : records) {
            if (rec instanceof ARecord) {
                inetAddress = ((ARecord) rec).getAddress();
                break;
            }
        }

        if (inetAddress == null) {
            sendError(conn.client, SocksReplyCodes.REP_HOST_UNREACHABLE);
            conn.close();
            removeConnectionHashMaps(conn);
            return;
        }
        conn.ipAddress = inetAddress;

        try {
            startRemoteConnect(conn);
            conn.state = Connection.State.CONNECTING;
        } catch (IOException e) {
            sendError(conn.client, SocksReplyCodes.REP_GENERAL_FAILURE);
            conn.close();
            removeConnectionHashMaps(conn);
        }
    }

    private static void finishConnect(SelectionKey key) throws IOException {
        SocketChannel sc = (SocketChannel) key.channel();
        Connection conn = channelsConnection.get(sc);
        if (conn == null) return;
        try {
            if (sc.finishConnect()) {
                key.interestOps(SelectionKey.OP_READ);
                if (conn.client != null && conn.state != Connection.State.CLOSED) {
                    sendSocksSuccess(conn.client, conn.ipAddress != null ? conn.ipAddress :
                            InetAddress.getByAddress(new byte[]{0,0,0,0}), conn.port);
                    conn.state = Connection.State.DATA_TRANSFER;
                }
            }
        } catch (IOException e) {
            sendError(conn.client, SocksReplyCodes.REP_CONNECTION_REFUSED);
            conn.close();
            removeConnectionHashMaps(conn);
        }
    }

    private static void handleRead(SelectionKey key) throws IOException {
        SocketChannel socketChannel = (SocketChannel) key.channel();
        Connection conn = channelsConnection.get(socketChannel);
        if (socketChannel == conn.client) {
            handleReadFromClient(conn);
        } else {
            handleReadFromRemote(conn);
        }
    }

    private static void handleReadFromClient(Connection conn) throws IOException {
        int read;
        if (conn.state == Connection.State.AUTHENITICATION || conn.state == Connection.State.REQUEST) {
            read = conn.client.read(conn.bufferConnection);
            if (read == -1) {
                conn.close();
                removeConnectionHashMaps(conn);
                return;
            }
            conn.bufferConnection.flip();
            processBufferConnection(conn);
            conn.bufferConnection.compact();
        } else if (conn.state == Connection.State.DATA_TRANSFER) {
            read = conn.client.read(conn.clientToRemote);
            if (read == -1) {
                SelectionKey clientKey = conn.client.keyFor(selector);
                if (clientKey != null) {
                    clientKey.interestOps(clientKey.interestOps() & ~SelectionKey.OP_READ);
                }
            }
            conn.clientToRemote.flip();
            if (conn.remote != null) {
                SelectionKey remoteKey = conn.remote.keyFor(selector);
                if (remoteKey != null) {
                    remoteKey.interestOps(remoteKey.interestOps() | SelectionKey.OP_WRITE);
                }
            }
            conn.clientToRemote.compact();
        }
    }

    private static void handleReadFromRemote(Connection conn) throws IOException {
        int r = conn.remote.read(conn.remoteToClient);
        if (r == -1) {
            SelectionKey remoteKey = conn.remote.keyFor(selector);
            if (remoteKey != null) {
                remoteKey.interestOps(remoteKey.interestOps() & ~SelectionKey.OP_READ);
            }
            SelectionKey clientKey = conn.client.keyFor(selector);
            if (clientKey != null) {
                clientKey.interestOps(clientKey.interestOps() | SelectionKey.OP_WRITE);
            }
        } else if (r > 0) {
            conn.remoteToClient.flip();
            SelectionKey clientKey = conn.client.keyFor(selector);
            if (clientKey != null) {
                clientKey.interestOps(clientKey.interestOps() | SelectionKey.OP_WRITE);
            }
            conn.remoteToClient.compact();

        }
    }

    private static void handleWrite(SelectionKey key) throws IOException {
        SocketChannel sc = (SocketChannel) key.channel();
        Connection conn = channelsConnection.get(sc);
        if (conn == null) return;

        if (sc == conn.client) {
            conn.remoteToClient.flip();
            conn.client.write(conn.remoteToClient);
            conn.remoteToClient.compact();
            if (conn.remoteToClient.position() == 0) {
                key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
            }

        } else {
            conn.clientToRemote.flip();
            conn.remote.write(conn.clientToRemote);
            conn.clientToRemote.compact();
            if (conn.clientToRemote.position() == 0) {
                key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
            }

        }
    }

    private static void processBufferConnection(Connection conn) throws IOException {
        ByteBuffer buffer = conn.bufferConnection;
        buffer.mark();
        if (conn.state == Connection.State.AUTHENITICATION) {
            if (buffer.remaining() < 2) { buffer.reset(); return; }
            processAuthenitication(conn, buffer);
            return;
        }

        if (conn.state == Connection.State.REQUEST) {
            if (buffer.remaining() < 4) { buffer.reset(); return; }
            processRequestParsing(conn, buffer);
        }
    }

    private static void processAuthenitication(Connection conn, ByteBuffer byteBuffer) throws IOException {
        byte version = byteBuffer.get();
        byte nmethods = byteBuffer.get();
        if ((byteBuffer.remaining()) < nmethods) { byteBuffer.reset(); return; }
        boolean noAuth = false;
        for (int i = 0; i < nmethods; i++) {
            byte method = byteBuffer.get();
            if (method == 0x00) {
                noAuth = true;
            }
        }
        //proxy -> client
        ByteBuffer response = ByteBuffer.wrap(new byte[]{0x05, (noAuth ? 0x00 : (byte)0xFF)});
        conn.client.write(response);
        if (!noAuth) {
            conn.close();
            removeConnectionHashMaps(conn);
            return;
        }
        conn.state = Connection.State.REQUEST;
    }

    private static void processRequestParsing(Connection conn, ByteBuffer buffer) throws IOException {
        try {
            byte ver = buffer.get();
            byte cmd = buffer.get();
            byte rsv = buffer.get();
            byte atyp = buffer.get();
            if (ver != 0x05) {
                sendError(conn.client, SocksReplyCodes.REP_GENERAL_FAILURE);
                conn.close();
                removeConnectionHashMaps(conn);
                return;
            }
            if (cmd != 0x01) {
                sendError(conn.client, SocksReplyCodes.REP_COMMAND_NOT_SUPPORTED);
                conn.close();
                removeConnectionHashMaps(conn);
                return;
            }
            if (atyp == 0x01) {
                if (buffer.remaining() < 4 + 2) {
                    buffer.reset();
                    return;
                }
                byte[] ip = new byte[4];
                buffer.get(ip);
                int port = ((buffer.get() & 0xFF) << 8) | (buffer.get() & 0xFF);
                conn.port = port;
                conn.ipAddress = InetAddress.getByAddress(ip);
                startRemoteConnect(conn);
                conn.state = Connection.State.CONNECTING;
            } else if (atyp == 0x03) {
                if (buffer.remaining() < 1) {
                    buffer.reset();
                    return;
                }
                int len = buffer.get() & 0xFF;
                if (buffer.remaining() < len + 2) {
                    buffer.reset();
                    return;
                }
                byte[] nameBytes = new byte[len];
                buffer.get(nameBytes);
                String name = new String(nameBytes, StandardCharsets.UTF_8);
                int port = ((buffer.get() & 0xFF) << 8) | (buffer.get() & 0xFF);
                conn.port = port;
                conn.nameResolveDns = name;
                startDnsResolve(conn, name);
                conn.state = Connection.State.RESOLVING;
            } else {
                sendError(conn.client, SocksReplyCodes.REP_ADDRESS_TYPE_NOT_SUPPORTED);
                conn.close();
                removeConnectionHashMaps(conn);
            }
        } catch (UnknownHostException e) {
            sendError(conn.client, SocksReplyCodes.REP_HOST_UNREACHABLE);
            conn.close();
            removeConnectionHashMaps(conn);
        }
    }

    private static void startRemoteConnect(Connection conn) throws IOException {
        InetSocketAddress remoteAddr = new InetSocketAddress(conn.ipAddress, conn.port);
        SocketChannel remote = SocketChannel.open();
        remote.configureBlocking(false);
        remote.connect(remoteAddr);
        conn.remote = remote;
        channelsConnection.put(remote, conn);
        remote.register(selector, SelectionKey.OP_CONNECT, conn);
    }

    private static void startDnsResolve(Connection conn, String nameString) {
        try {
        Message message = new Message();
        int id;
        do {
            id = rand.nextInt(0xFF);
        } while (dnsMap.containsKey(id));
        message.getHeader().setID(id);
            Name name = Name.fromString(nameString + ".");
            Record record = Record.newRecord(name, Type.A, DClass.IN);
            message.addRecord(record, Section.QUESTION);
            ByteBuffer buf = ByteBuffer.wrap(message.toWire());
            dnsChannel.send(buf, dnsResover);
            dnsMap.put(id, new DnsRequestResolve(id, conn, nameString));
        } catch (Exception e) {
            sendError(conn.client, SocksReplyCodes.REP_HOST_UNREACHABLE);
            conn.close();
            removeConnectionHashMaps(conn);
        }
    }


    private static void sendError(SocketChannel client, byte rep) {
        try {
            ByteBuffer response = ByteBuffer.allocate(10);
            response.put((byte)0x05); //ver
            response.put(rep);
            response.put((byte)0x00); // rsv
            response.put((byte)0x01); //atyp
            for (int i = 0; i < 4; i++) {
                response.put((byte)0x00); //bnd.addr
            }
            response.putShort((short)0); //bnd.port
            response.flip();
            client.write(response);
        } catch (IOException e) {
            System.err.println(e.getMessage());
        }
    }

    private static void sendSocksSuccess(SocketChannel client, InetAddress boundAddr, int boundPort) {
        try {
            byte[] addrBytes = boundAddr != null ? boundAddr.getAddress() : new byte[]{0,0,0,0};
            ByteBuffer response = ByteBuffer.allocate(10);
            response.put((byte)0x05);
            response.put(SocksReplyCodes.REP_SUCCEEDED);
            response.put((byte)0x00); // rsv
            response.put((byte)0x01); // ipv4
            response.put(addrBytes);
            response.putShort((short)boundPort);
            response.flip();
            client.write(response);
        } catch (IOException e) {
            System.err.println(e.getMessage());
        }
    }


    private static void cleanupPendingDns() {
        Instant now = Instant.now();
        List<Integer> toRemove = new ArrayList<>();
        for (Map.Entry<Integer, DnsRequestResolve> entry : dnsMap.entrySet()) {
            if (now.minusSeconds(10).isAfter(entry.getValue().since)) {
                DnsRequestResolve dnsRequestResolve = entry.getValue();
                sendError(dnsRequestResolve.conn.client, SocksReplyCodes.REP_HOST_UNREACHABLE);
                dnsRequestResolve.conn.close();
                removeConnectionHashMaps(dnsRequestResolve.conn);
                toRemove.add(entry.getKey());
            }
        }
        for (Integer id : toRemove) dnsMap.remove(id);
    }

    private static void removeConnectionHashMaps(Connection conn) {
        try {
            if (conn.client != null) channelsConnection.remove(conn.client);
        } catch (Exception ignored) {}
        try {
            if (conn.remote != null) channelsConnection.remove(conn.remote);
        } catch (Exception ignored) {}
    }

    private static void shutdown() {
        try {
            for (Connection c : new ArrayList<>(channelsConnection.values())) {
                if (c != null) {
                    c.close();
                }
            }
            channelsConnection.clear();
            dnsMap.clear();
            if (dnsChannel != null && dnsChannel.isOpen()) dnsChannel.close();
            if (serverChannel != null && serverChannel.isOpen()) serverChannel.close();
            if (selector != null && selector.isOpen()) selector.close();
        } catch (IOException e) {
            System.err.println(e.getMessage());
        }
    }
}