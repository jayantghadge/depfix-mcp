package dev.depfix.mcp.github;

/**
 * Validates GitHub repository URLs and normalizes them to owner/repo (+ optional branch).
 *
 * <p>Accepts only {@code https://github.com/OWNER/REPO} with an optional branch supplied
 * separately or via {@code /tree/BRANCH} URLs. Rejects all other hosts and shapes so the
 * server can never be tricked into fetching arbitrary remote content.
 */
public final class RepositoryUrlParser {

  private RepositoryUrlParser() {}

  public record ParsedUrl(String owner, String repo) {}

  public static ParsedUrl parse(String repositoryUrl) {
    if (repositoryUrl == null || repositoryUrl.isBlank()) {
      throw new IllegalArgumentException("repository_url is required.");
    }
    String trimmed = repositoryUrl.trim().replaceAll("/+$", "");
    java.net.URI uri;
    try {
      uri = java.net.URI.create(trimmed);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Malformed repository URL: " + repositoryUrl);
    }
    if (!"https".equalsIgnoreCase(uri.getScheme())) {
      throw new IllegalArgumentException("Only https GitHub URLs are accepted: " + repositoryUrl);
    }
    if (!"github.com".equalsIgnoreCase(uri.getHost())) {
      throw new IllegalArgumentException(
          "Unsupported host '" + uri.getHost() + "'. Only github.com URLs are accepted.");
    }
    if (uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null) {
      throw new IllegalArgumentException("URL must not contain credentials, query, or fragment.");
    }
    String path = uri.getPath() == null ? "" : uri.getPath().replaceAll("^/+|/+$", "");
    String[] seg = path.split("/");
    if (seg.length < 2 || seg[0].isBlank() || seg[1].isBlank()) {
      throw new IllegalArgumentException(
          "Expected https://github.com/OWNER/REPOSITORY, got: " + repositoryUrl);
    }
    String owner = seg[0];
    String repo = seg[1].endsWith(".git") ? seg[1].substring(0, seg[1].length() - 4) : seg[1];
    if (!owner.matches("[A-Za-z0-9_.-]+") || !repo.matches("[A-Za-z0-9_.-]+")) {
      throw new IllegalArgumentException("Invalid owner or repository name in URL.");
    }
    // Allow /tree/BRANCH or /blob/BRANCH/... shapes but ignore anything deeper than owner/repo.
    // The branch itself must come from the explicit `branch` tool parameter (or default branch).
    if (seg.length > 2 && !"tree".equals(seg[2]) && !"blob".equals(seg[2])) {
      throw new IllegalArgumentException(
          "Unsupported URL form. Use https://github.com/OWNER/REPOSITORY with an optional branch parameter.");
    }
    return new ParsedUrl(owner, repo);
  }

  /** Extracts a branch from /tree/BRANCH or /blob/BRANCH/... URLs when present. */
  public static String extractBranchFromUrl(String repositoryUrl) {
    try {
      java.net.URI uri = java.net.URI.create(repositoryUrl.trim().replaceAll("/+$", ""));
      String[] seg = (uri.getPath() == null ? "" : uri.getPath().replaceAll("^/+|/+$", "")).split("/");
      if (seg.length >= 4 && ("tree".equals(seg[2]) || "blob".equals(seg[2]))) {
        return seg[3];
      }
    } catch (RuntimeException ignored) {
      // caller falls back to explicit branch / default branch
    }
    return null;
  }
}
