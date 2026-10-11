package dev.depfix.mcp.vuln;

public class KevException extends RuntimeException {
  public KevException(String message) {
    super(message);
  }

  public KevException(String message, Throwable cause) {
    super(message, cause);
  }
}
