package dev.depfix.mcp.vuln;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Read-only client for the NVD CVE API, used to fill severity gaps OSV leaves
 * (findings with no CVSS vector). Findings already scored from OSV vectors
 * never trigger a lookup.
 *
 * <p>Responses are cached on disk (default TTL 24h) so repeat scans skip the
 * network. Live calls respect NVD rate limits by spacing requests (6.5s
 * anonymous, 0.7s with an API key). A 404 (unknown CVE) is data, not failure;
 * transport and rate-limit errors throw so the caller can mark enrichment
 * degraded instead of silently skipping.
 */
@Component
public class NvdClient {

  public record NvdDetails(
      String cveId,
      String description,
      Double baseScore,
      String baseSeverity,
      String vectorString,
      String metricsVersion,
      List<String> references) {}

  private final HttpClient http;
  private final ObjectMapper mapper;
  private final String apiBaseUrl;
  private final String apiKey;
  private final long requestTimeoutS;
  private final long spacingMs;
  private final String userAgent;
  private final java.nio.file.Path cacheDir;
  private final long ttlSeconds;
  private long lastCallMs = 0;

  public NvdClient(
      HttpClient http,
      ObjectMapper mapper,
      @Value("${depfix.nvd.api-base-url:https://services.nvd.nist.gov/rest/json/cves/2.0}") String apiBaseUrl,
      @Value("${NVD_API_KEY:}") String apiKey,
      @Value("${depfix.nvd.request-timeout-s:25}") long requestTimeoutS,
      @Value("${depfix.nvd.spacing-ms:6500}") long spacingMs,
      @Value("${depfix.nvd.cache-dir:${user.home}/.cache/depfix/nvd}") String cacheDir,
      @Value("${depfix.nvd.ttl-hours:24}") long ttlHours,
      @Value("${depfix.github.user-agent:depfix-mcp/0.1.0}") String userAgent) {
    this.http = http;
    this.mapper = mapper;
    this.apiBaseUrl = apiBaseUrl.endsWith("/") ? apiBaseUrl.substring(0, apiBaseUrl.length() - 1) : apiBaseUrl;
    this.apiKey = apiKey == null ? "" : apiKey.trim();
    this.requestTimeoutS = requestTimeoutS;
    this.spacingMs = Math.max(0, spacingMs);
    this.cacheDir = java.nio.file.Path.of(cacheDir);
    this.ttlSeconds = Math.max(60, ttlHours * 3600);
    this.userAgent = userAgent;
  }

  public boolean hasApiKey() {
    return !apiKey.isBlank();
  }

  /**
   * Enrichment for one CVE. Served from disk cache when fresh; otherwise fetched
   * live (throttled) and cached. Empty when NVD has no record — cached as such
   * so repeats stay fast. Throws on API failure.
   */
  public synchronized Optional<NvdDetails> lookup(String cveId) {
    String key = cveId.strip().toUpperCase(java.util.Locale.ROOT);
    Optional<NvdDetails> cached = readCache(key);
    if (cached != null) return cached;
    throttle();
    try {
      HttpRequest.Builder b = HttpRequest.newBuilder()
          .uri(URI.create(apiBaseUrl + "?cveId=" + URLEncoder.encode(cveId, StandardCharsets.UTF_8)))
          .timeout(Duration.ofSeconds(requestTimeoutS))
          .header("Accept", "application/json")
          .header("User-Agent", userAgent)
          .GET();
      if (!apiKey.isBlank()) {
        b.header("apiKey", apiKey);
      }
      HttpResponse<String> res = http.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
      if (res.statusCode() == 404) return Optional.empty();
      if (res.statusCode() == 403 || res.statusCode() == 429) {
        throw new NvdException("NVD rate limit or access denied (HTTP " + res.statusCode()
            + "). Configure NVD_API_KEY for higher limits and retry.");
      }
      if (res.statusCode() != 200) {
        throw new NvdException("NVD API returned HTTP " + res.statusCode() + ". Retry later.");
      }
      Optional<NvdDetails> details = parse(key, mapper.readTree(res.body()));
      writeCache(key, res.body());
      return details;
    } catch (NvdException e) {
      throw e;
    } catch (java.net.http.HttpTimeoutException e) {
      throw new NvdException("NVD request timed out. Retry later.", e);
    } catch (java.io.IOException | InterruptedException e) {
      if (e instanceof InterruptedException) Thread.currentThread().interrupt();
      throw new NvdException("Network error contacting NVD: " + e.getMessage(), e);
    } catch (Exception e) {
      throw new NvdException("Failed to query NVD: " + e.getMessage(), e);
    }
  }

  /** Cached lookup result, or null on cache miss/staleness. Empty means "NVD has no record". */
  private Optional<NvdDetails> readCache(String key) {
    java.nio.file.Path file = cacheDir.resolve(key + ".json");
    try {
      if (!java.nio.file.Files.isRegularFile(file)) return null;
      long age = java.time.Instant.now().getEpochSecond()
          - java.nio.file.Files.getLastModifiedTime(file).toInstant().getEpochSecond();
      if (age >= ttlSeconds) return null;
      return parse(key, mapper.readTree(java.nio.file.Files.readString(file, StandardCharsets.UTF_8)));
    } catch (Exception e) {
      return null;
    }
  }

  private void writeCache(String key, String body) {
    try {
      java.nio.file.Files.createDirectories(cacheDir);
      java.nio.file.Files.writeString(cacheDir.resolve(key + ".json"), body, StandardCharsets.UTF_8);
    } catch (Exception ignored) {
      // Cache is best-effort; live data is still returned.
    }
  }

  private void throttle() {    long now = System.currentTimeMillis();
    long wait = spacingMs - (now - lastCallMs);
    if (wait > 0) {
      try {
        Thread.sleep(wait);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new NvdException("NVD throttling interrupted", e);
      }
    }
    lastCallMs = System.currentTimeMillis();
  }

  static Optional<NvdDetails> parse(String cveId, JsonNode root) {
    JsonNode vulns = root.path("vulnerabilities");
    if (!vulns.isArray() || vulns.isEmpty()) return Optional.empty();
    JsonNode cve = vulns.path(0).path("cve");
    String description = null;
    for (JsonNode d : cve.withArray("descriptions")) {
      if ("en".equals(d.path("lang").asText())) {
        description = d.path("value").asText(null);
        break;
      }
    }
    if (description == null && !cve.withArray("descriptions").isEmpty()) {
      description = cve.withArray("descriptions").path(0).path("value").asText(null);
    }
    NvdMetric metric = firstMetric(cve, "cvssMetricV31", "3.1");
    if (metric == null) metric = firstMetric(cve, "cvssMetricV30", "3.0");
    if (metric == null) {
      NvdMetric v2 = firstMetric(cve, "cvssMetricV2", "2.0");
      if (v2 != null) {
        metric = new NvdMetric(v2.score(), v2Rating(v2.score()), v2.vector(), "2.0");
      }
    }
    List<String> refs = new ArrayList<>();
    for (JsonNode r : cve.withArray("references")) {
      String url = r.path("url").asText("");
      if (!url.isBlank() && refs.size() < 5) refs.add(url);
    }
    return Optional.of(new NvdDetails(cveId,
        description,
        metric == null ? null : metric.score(),
        metric == null ? null : metric.severity(),
        metric == null ? null : metric.vector(),
        metric == null ? null : metric.version(),
        refs));
  }

  private record NvdMetric(Double score, String severity, String vector, String version) {}

  private static NvdMetric firstMetric(JsonNode cve, String field, String version) {
    JsonNode arr = cve.path("metrics").path(field);
    if (!arr.isArray() || arr.isEmpty()) return null;
    JsonNode data = arr.path(0).path("cvssData");
    Double score = data.path("baseScore").isNumber() ? data.path("baseScore").asDouble() : null;
    String severity = data.path("baseSeverity").asText(null);
    String vector = data.path("vectorString").asText(null);
    if (score == null && severity == null) return null;
    return new NvdMetric(score, severity, vector, version);
  }

  private static String v2Rating(Double score) {
    if (score == null) return null;
    if (score >= 7.0) return "High";
    if (score >= 4.0) return "Medium";
    if (score > 0.0) return "Low";
    return "None";
  }
}
