package dev.depfix.mcp.vuln;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Read-only client for the OSV.dev vulnerability API.
 *
 * <p>Batch queries ({@code POST /v1/querybatch}) return id-only stubs, so every
 * implicated ID is hydrated via {@code GET /v1/vulns/{id}} (concurrently) before
 * any range confirmation. Responses are parsed defensively.
 */
@Component
public class OsvClient {

  private static final Logger log = LoggerFactory.getLogger(OsvClient.class);

  private final HttpClient http;
  private final ObjectMapper mapper;
  private final String apiBaseUrl;
  private final long requestTimeoutS;
  private final int batchSize;
  private final String userAgent;

  public OsvClient(
      HttpClient http,
      ObjectMapper mapper,
      @Value("${depfix.osv.api-base-url:https://api.osv.dev}") String apiBaseUrl,
      @Value("${depfix.osv.request-timeout-s:25}") long requestTimeoutS,
      @Value("${depfix.osv.batch-size:100}") int batchSize,
      @Value("${depfix.github.user-agent:depfix-mcp/0.1.0}") String userAgent) {
    this.http = http;
    this.mapper = mapper;
    this.apiBaseUrl = apiBaseUrl.endsWith("/") ? apiBaseUrl.substring(0, apiBaseUrl.length() - 1) : apiBaseUrl;
    this.requestTimeoutS = requestTimeoutS;
    this.batchSize = Math.max(1, Math.min(batchSize, 1000));
    this.userAgent = userAgent;
  }

  /** Queries OSV for each package@version. Returns one stub list per query, index-aligned. */
  public List<List<OsvSchema.Vuln>> queryBatch(List<OsvSchema.Query> queries) {
    List<List<OsvSchema.Vuln>> out = new ArrayList<>();
    for (int i = 0; i < queries.size(); i += batchSize) {
      out.addAll(queryBatchChunk(queries.subList(i, Math.min(queries.size(), i + batchSize))));
    }
    return out;
  }

  private List<List<OsvSchema.Vuln>> queryBatchChunk(List<OsvSchema.Query> queries) {
    try {
      ObjectNode root = mapper.createObjectNode();
      ArrayNode arr = root.putArray("queries");
      for (OsvSchema.Query q : queries) {
        ObjectNode query = arr.addObject();
        ObjectNode pkg = query.putObject("package");
        pkg.put("ecosystem", q.ecosystem());
        pkg.put("name", q.name());
        query.put("version", q.version());
      }
      String body = mapper.writeValueAsString(root);
      HttpRequest req = HttpRequest.newBuilder()
          .uri(URI.create(apiBaseUrl + "/v1/querybatch"))
          .timeout(Duration.ofSeconds(requestTimeoutS))
          .header("Content-Type", "application/json")
          .header("Accept", "application/json")
          .header("User-Agent", userAgent)
          .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
          .build();
      HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
      if (res.statusCode() != 200) {
        throw new OsvException("OSV API returned HTTP " + res.statusCode() + ". Retry later.");
      }
      JsonNode parsed = mapper.readTree(res.body());
      JsonNode results = parsed.path("results");
      List<List<OsvSchema.Vuln>> out = new ArrayList<>();
      for (int i = 0; i < queries.size(); i++) {
        JsonNode r = results.path(i);
        List<OsvSchema.Vuln> vulns = new ArrayList<>();
        for (JsonNode v : r.withArray("vulns")) {
          try {
            vulns.add(parseVuln(v));
          } catch (RuntimeException e) {
            log.warn("Skipping unparseable OSV entry: {}", e.getMessage());
          }
        }
        out.add(vulns);
      }
      return out;
    } catch (OsvException e) {
      throw e;
    } catch (java.net.http.HttpTimeoutException e) {
      throw new OsvException("OSV request timed out. Retry later.", e);
    } catch (java.io.IOException | InterruptedException e) {
      if (e instanceof InterruptedException) Thread.currentThread().interrupt();
      throw new OsvException("Network error contacting OSV: " + e.getMessage(), e);
    } catch (Exception e) {
      throw new OsvException("Failed to query OSV: " + e.getMessage(), e);
    }
  }

  /**
   * Hydrates full vuln records by ID. Requests run concurrently; IDs that 404,
   * time out, or fail to parse are simply absent — callers keep stub evidence.
   */
  public List<OsvSchema.Vuln> getByIds(List<String> ids) {
    List<String> distinct = new ArrayList<>(new java.util.LinkedHashSet<>(ids));
    List<java.util.concurrent.CompletableFuture<OsvSchema.Vuln>> futures = distinct.stream()
        .map(id -> {
          HttpRequest req = HttpRequest.newBuilder()
              .uri(URI.create(apiBaseUrl + "/v1/vulns/" + id))
              .timeout(Duration.ofSeconds(requestTimeoutS))
              .header("Accept", "application/json")
              .header("User-Agent", userAgent)
              .GET()
              .build();
          return http.sendAsync(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
              .thenApply(res -> res.statusCode() == 200 ? tryParse(res.body()) : null)
              .exceptionally(e -> null);
        })
        .toList();
    java.util.concurrent.CompletableFuture.allOf(futures.toArray(new java.util.concurrent.CompletableFuture[0])).join();
    List<OsvSchema.Vuln> out = new ArrayList<>();
    for (var f : futures) {
      OsvSchema.Vuln v = f.getNow(null);
      if (v != null && v.id() != null && !v.id().isBlank()) out.add(v);
    }
    return out;
  }

  private OsvSchema.Vuln tryParse(String body) {
    try {
      return parseVuln(mapper.readTree(body));
    } catch (Exception e) {
      log.warn("Skipping unparseable OSV entry: {}", e.getMessage());
      return null;
    }
  }

  static OsvSchema.Vuln parseVuln(JsonNode v) {
    List<String> refs = new ArrayList<>();
    for (JsonNode r : v.withArray("references")) {
      String url = r.path("url").asText("");
      if (!url.isBlank() && refs.size() < 8) refs.add(url);
    }
    return new OsvSchema.Vuln(
        v.path("id").asText(""),
        strings(v.withArray("aliases")),
        textOrNull(v, "summary"),
        textOrNull(v, "details"),
        textOrNull(v, "published"),
        textOrNull(v, "modified"),
        !v.path("withdrawn").isMissingNode(),
        parseSeverities(v.withArray("severity")),
        parseAffected(v.withArray("affected")),
        refs);
  }

  private static List<OsvSchema.Severity> parseSeverities(ArrayNode arr) {
    List<OsvSchema.Severity> out = new ArrayList<>();
    for (JsonNode s : arr) {
      out.add(new OsvSchema.Severity(s.path("type").asText(""), s.path("score").asText("")));
    }
    return out;
  }

  private static List<OsvSchema.Affected> parseAffected(ArrayNode arr) {
    List<OsvSchema.Affected> out = new ArrayList<>();
    for (JsonNode a : arr) {
      JsonNode pkg = a.path("package");
      List<OsvSchema.Range> ranges = new ArrayList<>();
      for (JsonNode r : a.withArray("ranges")) {
        List<OsvSchema.Event> events = new ArrayList<>();
        for (JsonNode e : r.withArray("events")) {
          events.add(new OsvSchema.Event(
              textOrNull(e, "introduced"), textOrNull(e, "fixed"),
              textOrNull(e, "last_affected"), textOrNull(e, "limit")));
        }
        ranges.add(new OsvSchema.Range(r.path("type").asText(""), events));
      }
      out.add(new OsvSchema.Affected(
          pkg.path("ecosystem").asText(""), pkg.path("name").asText(""),
          strings(a.withArray("versions")), ranges, null));
    }
    return out;
  }

  private static List<String> strings(ArrayNode arr) {
    List<String> out = new ArrayList<>();
    for (JsonNode n : arr) {
      if (n.isTextual() && !n.asText().isBlank()) out.add(n.asText());
    }
    return out;
  }

  private static String textOrNull(JsonNode n, String field) {
    JsonNode v = n.path(field);
    return (v.isTextual() && !v.asText().isBlank()) ? v.asText() : null;
  }
}
