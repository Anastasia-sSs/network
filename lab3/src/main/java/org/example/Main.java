package org.example;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URLEncoder;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

public class Main {

private static HttpClient httpClient;

private static final ObjectMapper mapper = new ObjectMapper();

private static final String OPENWEATHER_API_KEY = "23bc002930e0531aa6e92c7840bbedd5";
private static final String GRAPHHOPPER_API_KEY = "148ec065-cf41-42de-aecf-04bf268f4c12";


public static class Location {
    public double lat;
    public double lng;
    public String name;
}

public static class Weather {
    public double temp;
    public double windspeed;
    public double pressure;
    public double cloud;
    public String description;
}

public static class Place {
    public long pageId;
    public String title;
    public String extract;
    public double lat;
    public double lon;
}

public static class FinalResult {
    public Location location;
    public Weather weather;
    public List<Place> places;
}

private static CompletableFuture<HttpResponse<String>> getResponse(String url) {
    HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofMinutes(2))
            .header("User-Agent", "my-first-app-for-network")
            .GET()
            .build();
    return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString());
}

public static List<Location> parseGraphhopper(HttpResponse<String> response) {
    if (response.statusCode() != 200) {
        throw new RuntimeException("GraphHopper response:" + response.statusCode());
    }
    try {
        JsonNode root = mapper.readTree(response.body());
        JsonNode hits = root.path("hits");
        List<Location> list = new ArrayList<>();

        for (JsonNode hit : hits) {
            Location location = new Location();
            location.lng = hit.path("point").path("lng").asDouble();
            location.lat = hit.path("point").path("lat").asDouble();
            String name = hit.path("name").asText("");
            String city = hit.path("city").asText("");
            location.name = name + " " + city;
            list.add(location);
        }
        return list;
    } catch (JsonProcessingException e) {
        throw new RuntimeException("parse GraphHopper failed");
    }
}

public static Weather parseOpenWeather(HttpResponse<String> response) {
    if (response.statusCode() != 200) {
        throw new RuntimeException("OpenWeather response " + response.statusCode());
    }
    try {
        JsonNode root = mapper.readTree(response.body());
        Weather weather = new Weather();
        weather.temp = root.path("main").path("temp").asDouble(Double.NaN);
        weather.pressure = root.path("main").path("pressure").asDouble(Double.NaN);
        weather.windspeed = root.path("wind").path("speed").asDouble(Double.NaN);
        weather.cloud = root.path("clouds").path("all").asDouble(Double.NaN);
        weather.description = root.path("weather").path("description").asText();
        return weather;
    } catch (JsonProcessingException e) {
        throw new RuntimeException("parse OpenWeather failed");
    }
}

public static List<Place> parsePlacesWiki(HttpResponse<String> response) {
    if (response.statusCode() != 200) {
        throw new RuntimeException("WeatherWiki response " + response.statusCode());
    }
    try {
        JsonNode root = mapper.readTree(response.body());
        JsonNode geosearch = root.path("query").path("geosearch");
        List<Place> list = new ArrayList<>();
        for (JsonNode g : geosearch) {
            Place place = new Place();
            place.pageId = g.path("pageid").asLong();
            place.title = g.path("title").asText();
            place.lat = g.path("lat").asDouble();
            place.lon = g.path("lon").asDouble();
            list.add(place);
        }
        return list;
    } catch (IOException e) {
        throw new RuntimeException("parse WeatherWiki failed");
    }
}

public static Place parseDescriptionWiki(HttpResponse<String> response, Place place) {
        if (response.statusCode() != 200) {
            throw new RuntimeException("DescriptionWiki response " + response.statusCode());
        }
        try {
            JsonNode root = mapper.readTree(response.body());
            JsonNode page = root.path("query").path("pages").path(String.valueOf(place.pageId));
            place.extract = page.path("extract").asText();
            return place;
        } catch (IOException e) {
            throw new RuntimeException("parse DescriptionWiki failed", e);
        }
}

public static CompletableFuture<List<Location>> searchLocation(String string) {
    String url = "https://graphhopper.com/api/1/geocode?q=" + URLEncoder.encode(string, StandardCharsets.UTF_8)
            + "&limit=3&key=" + GRAPHHOPPER_API_KEY;

    return getResponse(url).thenApply(Main::parseGraphhopper);
}

public static CompletableFuture<Weather> getWeather(Location loc) {
    String url = String.format(Locale.US,
            "https://api.openweathermap.org/data/2.5/weather?lat=%.5f&lon=%.5f&appid=%s&units=metric",
            loc.lat, loc.lng, OPENWEATHER_API_KEY);

    return getResponse(url).thenApply(Main::parseOpenWeather);
}

public static CompletableFuture<List<Place>> getPlaces(Location location) {
    String url = "https://en.wikipedia.org/w/api.php?action=query&list=geosearch&gscoord="
            +  URLEncoder.encode(String.format(Locale.US, "%.5f|%.5f", location.lat, location.lng),
            StandardCharsets.UTF_8) + "&gsradius=10000&format=json&exchars=250";

    return getResponse(url).thenApply(Main::parsePlacesWiki);
}

public static CompletableFuture<Place> getPlaceDescription(Place place) {
    String url = "https://en.wikipedia.org/w/api.php?action=query&prop=extracts&exintro=&explaintext=&pageids="
            + place.pageId
            + "&format=json";
    return getResponse(url).thenApply(response -> parseDescriptionWiki(response, place));
}


public static CompletableFuture<FinalResult> getAll(Location location) {

    CompletableFuture<Weather> weatherFuture = getWeather(location);
    CompletableFuture<List<Place>> placesFuture = getPlaces(location);

    CompletableFuture<List<Place>> detailsFuture = placesFuture.thenCompose(places -> {
        if (places.isEmpty()) {
            return CompletableFuture.completedFuture(places);
        }
        List<CompletableFuture<Place>> detailFutures = new ArrayList<>();
        for (Place place : places) {
            detailFutures.add(getPlaceDescription(place));
        }
        CompletableFuture<Void> allDescriptions =
                CompletableFuture.allOf(detailFutures.toArray(new CompletableFuture[0]));

        return allDescriptions.thenApply(void_ -> places);
    });
    return weatherFuture.thenCombine(detailsFuture, (weather, listPlaces) -> {
        FinalResult result = new FinalResult();
        result.location = location;
        result.weather = weather;
        result.places = listPlaces;
        return result;
    });

}

public static CompletableFuture<Location> getUserLocation(List<Location> list) {
    return CompletableFuture.supplyAsync(() -> {
        for (int i = 0; i < list.size(); i++) {
            System.out.println(i + ") " + list.get(i).name + "[" + list.get(i).lat + ", " + list.get(i).lng + "]");
        }
        System.out.println("введи номер локации: ");
        Scanner scanner = new Scanner(System.in);
        int index = Integer.parseInt(scanner.nextLine().trim());
        return list.get(index);
    });
}


public static void main(String[] args) {
    Scanner scanner = new Scanner(System.in);
    System.out.println("введите локацию:");
    String string = scanner.nextLine().trim();
    if (string.isEmpty()) {
        System.out.println("запрос пуст");
        return;
    }

    httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(60))
            .build();

    CompletableFuture<List<Location>> searchFuture = searchLocation(string);

    CompletableFuture<FinalResult> future = searchFuture.thenCompose(locations -> {
        if (locations.isEmpty()) {
            FinalResult empty = new FinalResult();
            empty.location = null;
            empty.weather = null;
            empty.places = Collections.emptyList();
            return CompletableFuture.completedFuture(empty);
        }
        CompletableFuture<Location> userChooseFuture = getUserLocation(locations);

        CompletableFuture<FinalResult> futureFinal = userChooseFuture.thenCompose(Main::getAll);
        return futureFinal;
    });

    CompletableFuture<Void> finish = future.handle((result, ex) -> {
        if (ex != null) {
            System.out.println("произошла ошибка: " + ex.getMessage());
        } else {
            if (result.location == null) {
                System.out.println("локация не найдена");
            } else {
                System.out.println("локация: " + result.location.name);
                System.out.println("погода: ");
                if (result.weather == null)
                    System.out.println("нет данных");
                else {
                    System.out.println("описание: " + result.weather.description);
                    System.out.println("температура: " + result.weather.temp + " C");
                    System.out.println("скорость ветра: " + result.weather.windspeed + " м/с");
                    System.out.println("атмосферное давление: " + result.weather.pressure + " гПа");
                    System.out.println("облачность: " + result.weather.cloud + "%");
                }
                for (Place place : result.places) {
                    System.out.println("* " + place.title);
                    if (place.extract != null) {
                        System.out.println("-------------------------------------------------------------------------");
                        System.out.println(place.extract);
                        System.out.println("-------------------------------------------------------------------------");
                    } else {
                        System.out.println("нет описания");
                    }
                }
            }
        }
        return null;
    });

    try {
        finish.join();
    } catch (CompletionException e) {
        System.err.println(e.getMessage());
    }
    }
}