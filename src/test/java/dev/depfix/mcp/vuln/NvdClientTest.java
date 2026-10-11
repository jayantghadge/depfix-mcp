package dev.depfix.mcp.vuln;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class NvdClientTest {

  private HttpServer server;
  private NvdClient client;
  private java.nio.file.Path cacheDir;

  private static final String V31 = """
      {"vulnerabilities": [{"cve": {
        "id": "CVE-2024-0001",
        "descriptions": [{"lang": "en", "value": "Buffer overflow in Widget"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {
          "baseScore": 9.8, "baseSeverity": "CRITICAL",
          "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
        "references": [{"url": "https://example.com/a"}, {"url": "https://example.com/b"}]
      }}]}""";

  private static final String V2ONLY = """
      {"vulnerabilities": [{"cve": {
        "id": "CVE-2004-0001",
        "descriptions": [{"lang": "en", "value": "Old bug"}],
        "metrics": {"cvssMetricV2": [{"cvssData": {
          "baseScore": 7.5, "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}}]},
        "references": []
      }}]}""";

  @BeforeEach
  void start() throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/cves", ex -> {
      String q = ex.getRequestURI().getQuery();
      if (q != null && q.contains("CVE-2024-0001")) respond(ex, 200, V31);
      else if (q != null && q.contains("CVE-2004-0001")) respond(ex, 200, V2ONLY);
      else if (q != null && q.contains("CVE-2024-EMPTY")) respond(ex, 200, "{\"vulnerabilities\":[]}");
      else respond(ex, 404, "{\"message\":\"not found\"}");
    });
    server.start();
    String base = "http://127.0.0.1:" + server.getAddress().getPort() + "/cves";
    cacheDir = java.nio.file.Files.createTempDirectory("nvd-test");
    client = new NvdClient(
        HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(),
        new ObjectMapper(), base, "", 5, 0, cacheDir.toString(), 24, "depfix-test");
  }

  private static void respond(com.sun.net.httpserver.HttpExchange ex, int sc, String body) throws java.io.IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    ex.getResponseHeaders().add("Content-Type", "application/json");
    ex.sendResponseHeaders(sc, bytes.length);
    try (OutputStream os = ex.getResponseBody()) {
      os.write(bytes);
    }
  }

  @AfterEach
  void stop() throws Exception {
    if (server != null) server.stop(0);
    if (cacheDir != null && java.nio.file.Files.exists(cacheDir)) {
      try (var walk = java.nio.file.Files.walk(cacheDir)) {
        walk.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
          try {
            java.nio.file.Files.deleteIfExists(p);
          } catch (Exception ignored) {
          }
        });
      }
    }
  }

  @Test
  void parsesV31Metrics() {
    var details = client.lookup("CVE-2024-0001");
    assertTrue(details.isPresent());
    assertEquals(9.8, details.get().baseScore());
    assertEquals("CRITICAL", details.get().baseSeverity());
    assertEquals("3.1", details.get().metricsVersion());
    assertEquals("Buffer overflow in Widget", details.get().description());
    assertEquals(List.of("https://example.com/a", "https://example.com/b"), details.get().references());
  }

  @Test
  void fallsBackToV2Metrics() {
    var details = client.lookup("CVE-2004-0001");
    assertTrue(details.isPresent());
    assertEquals(7.5, details.get().baseScore());
    assertEquals("High", details.get().baseSeverity());
    assertEquals("2.0", details.get().metricsVersion());
  }

  @Test
  void unknownCveIsEmptyNotFailure() {
    assertTrue(client.lookup("CVE-2024-EMPTY").isEmpty());
    assertTrue(client.lookup("CVE-2099-NOPE").isEmpty());
  }

  @Test
  void diskCacheServesRepeatLookups() {
    var first = client.lookup("CVE-2024-0001");
    assertTrue(first.isPresent());
    server.stop(0);
    // Server dead: fresh cache still answers, no fetch attempted.
    var second = client.lookup("CVE-2024-0001");
    assertTrue(second.isPresent());
    assertEquals(first.get().baseScore(), second.get().baseScore());
  }
}
