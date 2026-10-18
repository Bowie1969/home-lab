package dev.willcyber.agentnpcs;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

public final class AgentGateway {
    private static final Gson GSON = new Gson();
    private final HttpClient client;
    private final URI baseUri;
    private final String token;

    public AgentGateway(URI baseUri, String token) {
        String normalized = baseUri.toString().replaceAll("/+$", "");
        this.baseUri = URI.create(normalized);
        this.token = token == null ? "" : token.strip();
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();
    }

    public List<AgentSnapshot> listAgents() throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(baseUri.resolve("/api/agents"))
                .timeout(Duration.ofSeconds(5))
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        requireSuccess(response);
        AgentList decoded = GSON.fromJson(response.body(), AgentList.class);
        return decoded == null || decoded.agents == null ? List.of() : List.copyOf(decoded.agents);
    }

    public void sendCommand(String agentId, String action, String task) throws IOException, InterruptedException {
        JsonObject payload = new JsonObject();
        payload.addProperty("action", action);
        if (task != null) {
            payload.addProperty("task", task);
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder(baseUri.resolve("/api/agents/" + agentId + "/commands"))
                .timeout(Duration.ofSeconds(5))
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(payload)));
        if (!token.isBlank()) {
            builder.header("Authorization", "Bearer " + token);
        }
        HttpRequest request = builder.build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        requireSuccess(response);
    }

    private static void requireSuccess(HttpResponse<String> response) throws IOException {
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Agent gateway returned HTTP " + response.statusCode() + ": " + response.body());
        }
    }

    private static final class AgentList {
        List<AgentSnapshot> agents;
    }
}
