package dev.depfix.mcp.parser;

import dev.depfix.mcp.model.DetectedFile;

public interface DependencyAnalyzer {
  boolean supports(DetectedFile file);

  ParseOutcome analyze(String path, String content);
}
