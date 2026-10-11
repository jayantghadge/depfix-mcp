package dev.depfix.mcp.vuln;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Comparator;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class KevClientTest {

  private HttpServer server;
  private Path cacheDir;

  private static final String FEED = """
      {"catalogVersion": "2024.01.01", "count": 2, "vulnerabilities": [
        {"cveID": "CVE-2024-0001", "vendorProject": "Acme", "product": "Widget",
         "vulnerabilityName": "Widget RCE", "dateAdded": "2024-01-10",
         "shortDescription": "RCE in Widget", "requiredAction": "Apply updates",
         "dueDate": "2024-02-01", "notes": ""},
        {"cveID": "cve-2024-0002", "vendorProject": "Acme", "product": "Gadget",
         "vulnerabilityName": "Gadget XSS", "dateAdded": "2024-01-11",
         "shortDescription": "XSS", "requiredAction": "Apply updates",
         "dueDate": "2024-02-02", "notes": ""}
      ]}""";

  @AfterEach
  void stop() throws Exception {
    if (server != null) server.stop(0);
    if (cacheDir != null && Files.exists(cacheDir)) {
      try (var walk = Files.walk(cacheDir)) {
        walk.sorted(Comparator.reverseOrder()).forEach(p -> {
          try {
            Files.deleteIfExists(p);
          } catch (Exception ignored) {
          }
        });
      }
    }
  }

  private KevClient client(String feedPath) throws Exception {
    cacheDir = Files.createTempDirectory("kev-test");
    String base = "http://127.0.0.1:" + server.getAddress().getPort();
    return new KevClient(
        HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(),
        new ObjectMapper(), base + feedPath, cacheDir.toString(), 24, 5, "depfix-test");
  }

  private void serve(String path, int sc, String body) throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(path, ex -> {
      byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
      ex.getResponseHeaders().add("Content-Type", "application/json");
      ex.sendResponseHeaders(sc, bytes.length);
      try (OutputStream os = ex.getResponseBody()) {
        os.write(bytes);
      }
    });
    server.start();
  }

  @Test
  void fetchesParsesAndCaches() throws Exception {
    serve("/kev.json", 200, FEED);
    var result = client("/kev.json").load();
    assertEquals(KevClient.Status.OK, result.status());
    assertEquals(2, result.byCveId().size());
    // Case-insensitive CVE lookup.
    assertTrue(result.lookup("cve-2024-0001").isPresent());
    assertEquals("2024-02-01", result.lookup("CVE-2024-0001").get().dueDate());
    assertTrue(result.lookup("CVE-2099-9999").isEmpty());
    assertTrue(Files.isRegularFile(cacheDir.resolve("kev.json")));
  }

  @Test
  void usesFreshCacheWithoutFetching() throws Exception {
    serve("/kev.json", 200, FEED);
    var c = client("/kev.json");
    assertEquals(KevClient.Status.OK, c.load().status());
    server.stop(0);
    // Server down but cache fresh → still OK, no fetch attempted.
    assertEquals(KevClient.Status.OK, c.load().status());
  }

  @Test
  void fallsBackToStaleCache() throws Exception {
    serve("/kev.json", 200, FEED);
    String base = "http://127.0.0.1:" + server.getAddress().getPort();
    cacheDir = Files.createTempDirectory("kev-test");
    var okClient = new KevClient(
        HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(),
        new ObjectMapper(), base + "/kev.json", cacheDir.toString(), 24, 5, "depfix-test");
    assertEquals(KevClient.Status.OK, okClient.load().status());
    // Age the cache beyond TTL, then kill the feed.
    Files.setLastModifiedTime(cacheDir.resolve("kev.json"),
        java.nio.file.attribute.FileTime.from(
            java.time.Instant.now().minus(java.time.Duration.ofHours(2))));
    server.stop(0);
    serve("/kev.json", 500, "{}");
    var retry = new KevClient(
        HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(),
        new ObjectMapper(), base + "/kev.json", cacheDir.toString(), 1, 5, "depfix-test");
    var result = retry.load();
    assertEquals(KevClient.Status.STALE_CACHE, result.status());
    assertEquals(2, result.byCveId().size());
  }

  @Test
  void unavailableWithoutCache() throws Exception {
    serve("/kev.json", 500, "{}");
    var result = client("/kev.json").load();
    assertEquals(KevClient.Status.UNAVAILABLE, result.status());
    assertTrue(result.byCveId().isEmpty());
    assertTrue(result.detail().contains("unavailable"));
  }

  @Test
  void skipsEntriesWithoutCveId() {
    try {
      var parsed = KevClient.parse("""
          {"vulnerabilities": [{"vendorProject": "x"}, {"cveID": "CVE-2024-1"}]}""");
      assertEquals(1, parsed.size());
      assertTrue(parsed.containsKey("CVE-2024-1"));
    } catch (KevException e) {
      fail("parse should not throw: " + e.getMessage());
    }
  }
}
