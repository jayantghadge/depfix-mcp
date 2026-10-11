package dev.depfix.mcp.tools;

import dev.depfix.mcp.github.GitHubClient;
import dev.depfix.mcp.github.GitHubException;
import dev.depfix.mcp.github.RepositoryRef;
import dev.depfix.mcp.github.RepositoryUrlParser;
import dev.depfix.mcp.model.AnalyzeResult;
import dev.depfix.mcp.model.ConfigureResult;
import dev.depfix.mcp.model.DetectResult;
import dev.depfix.mcp.model.DetectedFile;
import dev.depfix.mcp.service.DependencyInventoryService;
import dev.depfix.mcp.session.RepositorySession;
import java.util.ArrayList;
import java.util.List;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Component;

/**
 * Phase-1 MCP tools. All are read-only. Returning POJOs keeps output structured and
 * JSON-compatible for later phases.
 */
@Component
public class DepFixTools {

  private final GitHubClient github;
  private final DependencyInventoryService inventory;
  private final RepositorySession session;

  public DepFixTools(GitHubClient github, DependencyInventoryService inventory, RepositorySession session) {
    this.github = github;
    this.inventory = inventory;
    this.session = session;
  }

  @Tool(name = "configure_repository",
      description = "Validate a public GitHub repository URL, resolve the branch, and check read access. "
          + "Call this first. Only public repositories are supported.")
  public ConfigureResult configureRepository(
      @ToolParam(description = "Public GitHub repository URL, e.g. https://github.com/OWNER/REPO")
      String repository_url,
      @ToolParam(description = "Optional branch or ref. If omitted, the repo default branch is used.", required = false)
      String branch) {
    RepositoryUrlParser.ParsedUrl parsed;
    try {
      parsed = RepositoryUrlParser.parse(repository_url);
    } catch (IllegalArgumentException e) {
      return new ConfigureResult(null, null, null, false, false, false, null, e.getMessage());
    }
    String urlBranch = RepositoryUrlParser.extractBranchFromUrl(repository_url);
    String requested = branch != null && !branch.isBlank() ? branch.strip()
        : (urlBranch != null && !urlBranch.isBlank() ? urlBranch.strip() : null);

    GitHubClient.RepoInfo info;
    try {
      info = github.getRepoInfo(parsed.owner(), parsed.repo());
    } catch (GitHubException e) {
      return new ConfigureResult(parsed.owner(), parsed.repo(), requested, requested != null,
          false, false, null, e.getMessage());
    }

    String selected = requested;
    boolean explicit = requested != null;
    if (selected == null) {
      selected = info.defaultBranch();
    } else if (!github.checkBranchExists(parsed.owner(), parsed.repo(), selected)) {
      return new ConfigureResult(parsed.owner(), parsed.repo(), selected, true, false,
          info.isPrivate(), null,
          "Branch '" + selected + "' not found. Default branch is '" + info.defaultBranch() + "'.");
    }

    RepositoryRef existing = session.get();
    boolean replaced = existing != null
        && !(existing.owner().equals(parsed.owner()) && existing.repo().equals(parsed.repo())
            && selected.equals(existing.branch()));
    session.set(new RepositoryRef(parsed.owner(), parsed.repo(), selected));
    String msg = "Selected " + parsed.owner() + "/" + parsed.repo() + "@" + selected
        + (explicit ? " (explicit branch)" : " (default branch)")
        + (info.isPrivate() ? " [private]" : " [public]")
        + (replaced ? ". Previous selection replaced." : ".");
    return new ConfigureResult(parsed.owner(), parsed.repo(), selected, explicit, true,
        info.isPrivate(), msg, null);
  }

  @Tool(name = "detect_repository_ecosystems",
      description = "List dependency manifests/lockfiles in the selected repository and report parser support. "
          + "Detection is separate from extraction: unsupported files are reported, never silently skipped.")
  public DetectResult detectRepositoryEcosystems(
      @ToolParam(description = "GitHub repository URL (optional if configure_repository was already called)", required = false)
      String repository_url,
      @ToolParam(description = "Optional branch or ref", required = false)
      String branch) {
    RepositoryRef ref;
    try {
      ref = resolveRef(repository_url, branch);
    } catch (IllegalArgumentException e) {
      return new DetectResult(null, null, null, List.of(), List.of(), e.getMessage());
    }
    List<String> warnings = new ArrayList<>();
    try {
      List<DetectedFile> files = inventory.detect(ref.owner(), ref.repo(), ref.branch(), warnings);
      return new DetectResult(ref.owner(), ref.repo(), ref.branch(), files, warnings, null);
    } catch (GitHubException e) {
      return new DetectResult(ref.owner(), ref.repo(), ref.branch(), List.of(), warnings,
          e.getMessage());
    }
  }

  @Tool(name = "analyze_dependencies",
      description = "Build a structured dependency inventory (declared vs resolved versions, scopes, warnings) "
          + "from supported manifests/lockfiles. Read-only; never modifies the repo or executes its code.")
  public AnalyzeResult analyzeDependencies(
      @ToolParam(description = "GitHub repository URL (optional if configure_repository was already called)", required = false)
      String repository_url,
      @ToolParam(description = "Optional branch or ref", required = false)
      String branch) {
    RepositoryRef ref;
    try {
      ref = resolveRef(repository_url, branch);
    } catch (IllegalArgumentException e) {
      return new AnalyzeResult(null, null, null, null, List.of(), List.of(),
          java.util.Map.of(), java.util.Map.of(), List.of(), List.of(), e.getMessage());
    }
    return inventory.analyze(ref.owner(), ref.repo(), ref.branch());
  }

  private RepositoryRef resolveRef(String url, String branch) {
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
