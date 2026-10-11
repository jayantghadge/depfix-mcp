package dev.depfix.mcp.github;

/** Classified GitHub API failure so tools can return actionable, non-misleading messages. */
public class GitHubException extends RuntimeException {

  public enum Kind {
    NOT_FOUND,
    UNAUTHORIZED,
    FORBIDDEN,
    RATE_LIMITED,
    TRANSIENT,
    INVALID_BRANCH
  }

  private final Kind kind;
  private final int httpStatus;

  public GitHubException(Kind kind, int httpStatus, String message) {
    super(message);
    this.kind = kind;
    this.httpStatus = httpStatus;
  }

  public GitHubException(Kind kind, int httpStatus, String message, Throwable cause) {
    super(message, cause);
    this.kind = kind;
    this.httpStatus = httpStatus;
  }

  public Kind kind() {
    return kind;
  }

  public int httpStatus() {
    return httpStatus;
  }
}
