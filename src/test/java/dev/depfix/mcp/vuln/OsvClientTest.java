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

class OsvClientTest {

  private HttpServer server;
  private OsvClient client;

  private static final String BATCH = """
      {"results": [
        {"vulns": [{"id": "GHSA-test-1", "modified": "2024-02-01T00:00:00Z"}]},
        {},
        {"vulns": [{"id": "GHSA-test-2", "withdrawn": {}, "modified": "2024-01-01T00:00:00Z"}]}
      ]}""";

  private static final String FULL = """
      {
        "id": "GHSA-test-1",
        "aliases": ["CVE-2024-0001"],
        "summary": "Test vuln",
        "published": "2024-02-01T00:00:00Z",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{
          "package": {"ecosystem": "npm", "name": "left-pad"},
          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.3.1"}]}]
        }]
      }""";

  @BeforeEach
  void start() throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/v1/querybatch", ex -> respond(ex, 200, BATCH));
    server.createContext("/v1/vulns/GHSA-test-1", ex -> respond(ex, 200, FULL));
    server.start();
    String base = "http://127.0.0.1:" + server.getAddress().getPort();
    client = new OsvClient(
        HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(),
        new ObjectMapper(), base, 5, 100, "depfix-test");
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
  void stop() {
    if (server != null) server.stop(0);
  }

  @Test
  void parsesBatchAlignedStubs() {
    var out = client.queryBatch(List.of(
        new OsvSchema.Query("npm", "left-pad", "1.3.0"),
        new OsvSchema.Query("npm", "clean-pkg", "1.0.0"),
        new OsvSchema.Query("npm", "other", "2.0.0")));
    assertEquals(3, out.size());
    assertEquals("GHSA-test-1", out.get(0).get(0).id());
    assertTrue(out.get(1).isEmpty());
    assertTrue(out.get(2).get(0).withdrawn());
  }

  @Test
  void hydratesFullRecordsAndSkipsMissing() {
    var out = client.getByIds(List.of("GHSA-test-1", "GHSA-missing"));
    assertEquals(1, out.size());
    assertEquals("Test vuln", out.get(0).summary());
    assertEquals(List.of("CVE-2024-0001"), out.get(0).aliases());
    assertEquals(1, out.get(0).severities().size());
  }

  @Test
  void serverErrorBecomesOsvException() {
    server.removeContext("/v1/querybatch");
    server.createContext("/v1/querybatch", ex -> respond(ex, 500, "{}"));
    assertThrows(OsvException.class, () -> client.queryBatch(
        List.of(new OsvSchema.Query("npm", "x", "1.0.0"))));
  }
}
