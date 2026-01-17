package org.example;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

public class Connection {
    public static final int BUFFER_SIZE = 2 ^ 14;

    public SocketChannel client;
    public SocketChannel remote;
    public ByteBuffer clientToRemote = ByteBuffer.allocateDirect(BUFFER_SIZE);
    public ByteBuffer remoteToClient = ByteBuffer.allocateDirect(BUFFER_SIZE);
    public ByteBuffer bufferConnection = ByteBuffer.allocate(512);

    public State state = State.AUTHENITICATION;

    public String nameResolveDns;
    public InetAddress ipAddress;
    public int port;

    public enum State {AUTHENITICATION, REQUEST, RESOLVING, CONNECTING, DATA_TRANSFER, CLOSED}

    public void close() {
        try {
            if (client != null) {
                client.close();
            }
            if (remote != null) {
                remote.close();
            }
        } catch (IOException e) {
            System.err.println("close: " + e.getMessage());
        }
    }
}