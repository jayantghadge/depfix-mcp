package dev.depfix.mcp.vuln;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Read-only client for the CISA Known Exploited Vulnerabilities catalog.
 *
 * <p>The feed is cached on disk (default TTL 24h). Outcomes are explicit:
 * fresh data, stale cache fallback, or unavailable — the caller must surface
 * degraded states in the report and must never read them as "not exploited".
 */
@Component
public class KevClient {

  private static final Logger log = LoggerFactory.getLogger(KevClient.class);

  public record KevEntry(
      String cveId,
      String vendorProject,
      String product,
      String vulnerabilityName,
      String dateAdded,
      String shortDescription,
      String requiredAction,
      String dueDate) {}

  public enum Status { OK, STALE_CACHE, UNAVAILABLE }

  public record KevResult(Status status, Map<String, KevEntry> byCveId, String detail) {
    public Optional<KevEntry> lookup(String cveId) {
      if (cveId == null) return Optional.empty();
      return Optional.ofNullable(byCveId.get(cveId.strip().toUpperCase(java.util.Locale.ROOT)));
    }
  }

  private final HttpClient http;
  private final ObjectMapper mapper;
  private final String feedUrl;
  private final Path cacheFile;
  private final long ttlSeconds;
  private final long requestTimeoutS;
  private final String userAgent;

  public KevClient(
      HttpClient http,
      ObjectMapper mapper,
      @Value("${depfix.kev.feed-url:https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}") String feedUrl,
      @Value("${depfix.kev.cache-dir:${user.home}/.cache/depfix}") String cacheDir,
      @Value("${depfix.kev.ttl-hours:24}") long ttlHours,
      @Value("${depfix.kev.request-timeout-s:25}") long requestTimeoutS,
      @Value("${depfix.github.user-agent:depfix-mcp/0.1.0}") String userAgent) {
    this.http = http;
    this.mapper = mapper;
    this.feedUrl = feedUrl;
    this.cacheFile = Path.of(cacheDir, "kev.json");
    this.ttlSeconds = Math.max(60, ttlHours * 3600);
    this.requestTimeoutS = requestTimeoutS;
    this.userAgent = userAgent;
  }

  public KevResult load() {
    if (Files.isRegularFile(cacheFile) && isFresh(cacheFile)) {
      try {
        return new KevResult(Status.OK, parse(Files.readString(cacheFile, StandardCharsets.UTF_8)),
            "CISA KEV catalog loaded from local cache.");
      } catch (Exception e) {
        log.warn("KEV cache unreadable, refetching: {}", e.getMessage());
      }
    }
    try {
      String body = fetch();
      Map<String, KevEntry> entries = parse(body);
      try {
        Files.createDirectories(cacheFile.getParent());
        Files.writeString(cacheFile, body, StandardCharsets.UTF_8);
      } catch (Exception e) {
        log.warn("KEV cache write failed (continuing with live data): {}", e.getMessage());
      }
      return new KevResult(Status.OK, entries, "CISA KEV catalog fetched live.");
    } catch (KevException e) {
      if (Files.isRegularFile(cacheFile)) {
        try {
          return new KevResult(Status.STALE_CACHE, parse(Files.readString(cacheFile, StandardCharsets.UTF_8)),
              "CISA KEV fetch failed (" + e.getMessage() + "); using stale cache.");
        } catch (Exception ex) {
          log.warn("KEV stale cache unreadable: {}", ex.getMessage());
        }
      }
      return new KevResult(Status.UNAVAILABLE, Map.of(),
          "CISA KEV catalog unavailable (" + e.getMessage() + "); exploitation status unknown.");
    }
  }

  private boolean isFresh(Path file) {
    try {
      long age = Instant.now().getEpochSecond()
          - Files.getLastModifiedTime(file).toInstant().getEpochSecond();
      return age < ttlSeconds;
    } catch (Exception e) {
      return false;
    }
  }

  private String fetch() {
    try {
      HttpRequest req = HttpRequest.newBuilder()
          .uri(URI.create(feedUrl))
          .timeout(Duration.ofSeconds(requestTimeoutS))
          .header("Accept", "application/json")
          .header("User-Agent", userAgent)
          .GET()
          .build();
      HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
      if (res.statusCode() != 200) {
        throw new KevException("CISA KEV feed returned HTTP " + res.statusCode());
      }
      return res.body();
    } catch (KevException e) {
      throw e;
    } catch (java.net.http.HttpTimeoutException e) {
      throw new KevException("CISA KEV request timed out", e);
    } catch (java.io.IOException | InterruptedException e) {
      if (e instanceof InterruptedException) Thread.currentThread().interrupt();
      throw new KevException("network error: " + e.getMessage(), e);
    }
  }

  static Map<String, KevEntry> parse(String body) throws KevException {
    try {
      ObjectMapper m = new ObjectMapper();
      Map<String, KevEntry> out = new HashMap<>();
      for (JsonNode v : m.readTree(body).withArray("vulnerabilities")) {
        String cve = v.path("cveID").asText("").strip().toUpperCase(java.util.Locale.ROOT);
        if (cve.isEmpty()) continue;
        out.put(cve, new KevEntry(cve,
            text(v, "vendorProject"), text(v, "product"), text(v, "vulnerabilityName"),
            text(v, "dateAdded"), text(v, "shortDescription"),
            text(v, "requiredAction"), text(v, "dueDate")));
      }
      return out;
    } catch (KevException e) {
      throw e;
    } catch (Exception e) {
      throw new KevException("unparseable feed: " + e.getMessage(), e);
    }
  }

  private static String text(JsonNode n, String field) {
    JsonNode v = n.path(field);
    return (v.isTextual() && !v.asText().isBlank()) ? v.asText() : null;
  }
}
