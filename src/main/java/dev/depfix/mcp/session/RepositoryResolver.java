package dev.depfix.mcp.session;

import dev.depfix.mcp.github.GitHubClient;
import dev.depfix.mcp.github.GitHubException;
import dev.depfix.mcp.github.RepositoryRef;
import dev.depfix.mcp.github.RepositoryUrlParser;
import org.springframework.stereotype.Component;

/** Shared URL/session → RepositoryRef resolution used by all MCP tools. */
@Component
public class RepositoryResolver {

  private final GitHubClient github;
  private final RepositorySession session;

  public RepositoryResolver(GitHubClient github, RepositorySession session) {
    this.github = github;
    this.session = session;
  }

  public RepositoryRef resolve(String url, String branch) {
    if (url != null && !url.isBlank()) {
      var parsed = RepositoryUrlParser.parse(url);
      String urlBranch = RepositoryUrlParser.extractBranchFromUrl(url);
      String requested = branch != null && !branch.isBlank() ? branch.strip()
          : (urlBranch != null && !urlBranch.isBlank() ? urlBranch.strip() : null);
      if (requested != null) return new RepositoryRef(parsed.owner(), parsed.repo(), requested);
      try {
        String def = github.getRepoInfo(parsed.owner(), parsed.repo()).defaultBranch();
        return new RepositoryRef(parsed.owner(), parsed.repo(), def);
      } catch (GitHubException e) {
        throw new IllegalArgumentException(e.getMessage());
      }
    }
    RepositoryRef current = session.get();
    if (current == null) {
      throw new IllegalArgumentException(
          "No repository selected. Call configure_repository with a GitHub URL first, "
              + "or pass repository_url to this tool.");
    }
    if (branch != null && !branch.isBlank() && !branch.strip().equals(current.branch())) {
      return new RepositoryRef(current.owner(), current.repo(), branch.strip());
    }
    return current;
  }
}
