package dev.depfix.mcp.github;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class GitHubClientTest {

  private HttpServer server;
  private GitHubClient client;

  @BeforeEach
  void start() throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/", ex -> {
      String path = ex.getRequestURI().getPath();
      byte[] body;
      int sc = 200;
      ex.getResponseHeaders().add("Content-Type", "application/json");
      switch (path) {
        case "/repos/o/r" -> body = """
            {"default_branch":"develop","private":false}""".getBytes(StandardCharsets.UTF_8);
        case "/repos/o/missing" -> {
          sc = 404;
          body = "{\"message\":\"Not Found\"}".getBytes(StandardCharsets.UTF_8);
        }
        case "/repos/o/ratelimited" -> {
          sc = 403;
          ex.getResponseHeaders().add("X-RateLimit-Remaining", "0");
          body = "{\"message\":\"API rate limit exceeded\"}".getBytes(StandardCharsets.UTF_8);
        }
        default -> {
          sc = 404;
          body = "{\"message\":\"Not Found\"}".getBytes(StandardCharsets.UTF_8);
        }
      }
      ex.sendResponseHeaders(sc, body.length);
      try (OutputStream os = ex.getResponseBody()) {
        os.write(body);
      }
    });
    server.start();
    String base = "http://127.0.0.1:" + server.getAddress().getPort();
    client = new GitHubClient(
        HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(),
        new ObjectMapper(), base, 5, "depfix-test");
  }

  @AfterEach
  void stop() {
    if (server != null) server.stop(0);
  }

  @Test
  void resolvesDefaultBranchAnonymously() {
    var info = client.getRepoInfo("o", "r");
    assertEquals("develop", info.defaultBranch());
    assertFalse(info.isPrivate());
  }

  @Test
  void notFoundDoesNotClaimPrivate() {
    var ex = assertThrows(GitHubException.class, () -> client.getRepoInfo("o", "missing"));
    assertEquals(GitHubException.Kind.NOT_FOUND, ex.kind());
    assertFalse(ex.getMessage().toLowerCase().contains("private repository")
        && ex.getMessage().toLowerCase().startsWith("private"));
  }

  @Test
  void rateLimitClassifiedActionably() {
    var ex = assertThrows(GitHubException.class, () -> client.getRepoInfo("o", "ratelimited"));
    assertEquals(GitHubException.Kind.RATE_LIMITED, ex.kind());
    assertTrue(ex.getMessage().toLowerCase().contains("rate limit"));
  }
}
