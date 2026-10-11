package dev.depfix.mcp.vuln;

public class NvdException extends RuntimeException {
  public NvdException(String message) {
    super(message);
  }

  public NvdException(String message, Throwable cause) {
    super(message, cause);
  }
}
