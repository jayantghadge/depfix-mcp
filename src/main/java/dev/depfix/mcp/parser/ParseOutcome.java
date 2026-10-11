package dev.depfix.mcp.parser;

import dev.depfix.mcp.model.DependencyRecord;
import java.util.List;

public record ParseOutcome(List<DependencyRecord> dependencies, List<String> warnings) {
  public static ParseOutcome of(List<DependencyRecord> deps, List<String> warnings) {
    return new ParseOutcome(List.copyOf(deps), List.copyOf(warnings));
  }

  public static ParseOutcome empty(String warning) {
    return new ParseOutcome(List.of(), warning == null ? List.of() : List.of(warning));
  }
}
