package dev.depfix.mcp.github;

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
import java.util.Base64;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Read-only GitHub REST client. Anonymous access only: DepFix Phase 1 supports
 * public repositories. No credentials are accepted, stored, or logged.
 */
@Component
public class GitHubClient {

  private static final Logger log = LoggerFactory.getLogger(GitHubClient.class);

  private final HttpClient http;
  private final ObjectMapper mapper;
  private final String apiBaseUrl;
  private final long requestTimeoutS;
  private final String userAgent;

  public GitHubClient(
      HttpClient http,
      ObjectMapper mapper,
      @Value("${depfix.github.api-base-url:https://api.github.com}") String apiBaseUrl,
      @Value("${depfix.github.request-timeout-s:20}") long requestTimeoutS,
      @Value("${depfix.github.user-agent:depfix-mcp/0.1.0}") String userAgent) {
    this.http = http;
    this.mapper = mapper;
    this.apiBaseUrl = apiBaseUrl.endsWith("/") ? apiBaseUrl.substring(0, apiBaseUrl.length() - 1) : apiBaseUrl;
    this.requestTimeoutS = requestTimeoutS;
    this.userAgent = userAgent;
  }

  public record RepoInfo(String defaultBranch, boolean isPrivate) {}

  public RepoInfo getRepoInfo(String owner, String repo) {
    HttpResponse<String> res = get("/repos/" + seg(owner) + "/" + seg(repo), null);
    int sc = res.statusCode();
    if (sc == 200) {
      try {
        JsonNode n = mapper.readTree(res.body());
        String def = n.path("default_branch").asText("main");
        if (def.isBlank()) def = "main";
        boolean priv = n.path("private").asBoolean(false);
        return new RepoInfo(def, priv);
      } catch (Exception e) {
        throw new GitHubException(GitHubException.Kind.TRANSIENT, sc,
            "Failed to parse repository metadata. Retry later.", e);
      }
    }
    throw classify("repository metadata", sc, res);
  }

  public boolean checkBranchExists(String owner, String repo, String branch) {
    HttpResponse<String> res = get(
        "/repos/" + seg(owner) + "/" + seg(repo) + "/branches/" + seg(branch), null);
    return res.statusCode() == 200;
  }

  /** Lists all blob paths in the tree for {@code branch} (recursive). */
  public List<String> listTreePaths(String owner, String repo, String branch) {
    HttpResponse<String> res = get(
        "/repos/" + seg(owner) + "/" + seg(repo) + "/git/trees/" + seg(branch) + "?recursive=1", null);
    int sc = res.statusCode();
    if (sc == 200) {
      try {
        JsonNode root = mapper.readTree(res.body());
        if (root.path("truncated").asBoolean(false)) {
          log.warn("GitHub tree truncated for {}/{}@{}", owner, repo, branch);
        }
        List<String> paths = new ArrayList<>();
        for (JsonNode e : root.withArray("tree")) {
          if ("blob".equals(e.path("type").asText()) && e.hasNonNull("path")) {
            paths.add(e.get("path").asText());
          }
        }
        return paths;
      } catch (Exception e) {
        throw new GitHubException(GitHubException.Kind.TRANSIENT, sc,
            "Failed to parse repository tree. Retry later.", e);
      }
    }
    if (sc == 404) {
      throw new GitHubException(GitHubException.Kind.INVALID_BRANCH, sc,
          "Branch or repository not found: '" + branch + "'. Check the branch name.");
    }
    throw classify("repository tree", sc, res);
  }

  public record FileContent(String content, long size, boolean truncated) {}

  public FileContent fetchFile(String owner, String repo, String path, String branch, long maxBytes) {
    // Split path into encoded segments so slashes survive.
    StringBuilder enc = new StringBuilder();
    for (String s : path.split("/")) {
      if (!enc.isEmpty()) enc.append("/");
      enc.append(seg(s));
    }
    HttpResponse<String> res = get(
        "/repos/" + seg(owner) + "/" + seg(repo) + "/contents/" + enc + "?ref=" + seg(branch), null);
    int sc = res.statusCode();
    if (sc == 200) {
      try {
        JsonNode n = mapper.readTree(res.body());
        long size = n.path("size").asLong(0);
        String encoding = n.path("encoding").asText("");
        String b64 = n.path("content").asText("");
        if (size > maxBytes) {
          return new FileContent("", size, true);
        }
        if (!"base64".equalsIgnoreCase(encoding) || b64.isBlank()) {
          throw new GitHubException(GitHubException.Kind.TRANSIENT, sc,
              "Unsupported content encoding for file: " + path);
        }
        String cleaned = b64.replaceAll("\\s", "");
        byte[] bytes = Base64.getDecoder().decode(cleaned);
        if (bytes.length > maxBytes) {
          return new FileContent("", size, true);
        }
        return new FileContent(new String(bytes, StandardCharsets.UTF_8), size, false);
      } catch (GitHubException e) {
        throw e;
      } catch (Exception e) {
        throw new GitHubException(GitHubException.Kind.TRANSIENT, 200,
            "Failed to decode file content for: " + path, e);
      }
    }
    if (sc == 404) {
      throw new GitHubException(GitHubException.Kind.NOT_FOUND, sc, "File not found: " + path);
    }
    throw classify("file content", sc, res);
  }

  // ---- internals ----

  private HttpResponse<String> get(String path, String acceptOverride) {
    try {
      HttpRequest.Builder b = HttpRequest.newBuilder()
          .uri(URI.create(apiBaseUrl + path))
          .timeout(Duration.ofSeconds(requestTimeoutS))
          .header("Accept", acceptOverride != null ? acceptOverride : "application/vnd.github+json")
          .header("User-Agent", userAgent)
          .header("X-GitHub-Api-Version", "2022-11-28")
          .GET();
      return http.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    } catch (java.net.http.HttpTimeoutException e) {
      throw new GitHubException(GitHubException.Kind.TRANSIENT, 0,
          "GitHub request timed out. Retry later.", e);
    } catch (java.io.IOException | InterruptedException e) {
      if (e instanceof InterruptedException) Thread.currentThread().interrupt();
      throw new GitHubException(GitHubException.Kind.TRANSIENT, 0,
          "Network error contacting GitHub: " + e.getMessage(), e);
    }
  }

  private GitHubException classify(String what, int sc, HttpResponse<String> res) {
    String remaining = res.headers().firstValue("X-RateLimit-Remaining").orElse("");
    boolean rateLimited = "0".equals(remaining) || sc == 429
        || (sc == 403 && res.body() != null && res.body().toLowerCase().contains("rate limit"));
    if (rateLimited) {
      String reset = res.headers().firstValue("X-RateLimit-Reset").orElse("");
      return new GitHubException(GitHubException.Kind.RATE_LIMITED, sc,
          "GitHub API rate limit exceeded while fetching " + what + "."
              + (reset.isBlank() ? " Wait and retry." : " Limit resets at epoch " + reset + "."));
    }
    if (sc == 401) {
      return new GitHubException(GitHubException.Kind.UNAUTHORIZED, sc,
          "GitHub rejected the request while fetching " + what + ". Retry later.");
    }
    if (sc == 404) {
      return new GitHubException(GitHubException.Kind.NOT_FOUND, sc,
          "Repository, branch, or file not found while fetching " + what
              + ". DepFix supports public repositories only.");
    }
    if (sc == 403) {
      return new GitHubException(GitHubException.Kind.FORBIDDEN, sc,
          "GitHub denied access while fetching " + what
              + ". DepFix supports public repositories only.");
    }
    if (sc >= 500) {
      return new GitHubException(GitHubException.Kind.TRANSIENT, sc,
          "GitHub server error (" + sc + ") while fetching " + what + ". Retry later.");
    }
    return new GitHubException(GitHubException.Kind.TRANSIENT, sc,
        "Unexpected GitHub response (" + sc + ") while fetching " + what + ". Retry later.");
  }

  private static String seg(String s) {
    return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
  }
}
