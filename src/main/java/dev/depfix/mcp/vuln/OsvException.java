package dev.depfix.mcp.vuln;

public class OsvException extends RuntimeException {
  public OsvException(String message) {
    super(message);
  }

  public OsvException(String message, Throwable cause) {
    super(message, cause);
  }
}
