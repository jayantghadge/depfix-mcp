package dev.depfix.mcp.vuln;

import java.util.List;

/** Minimal OSV schema subset used by DepFix Phase 2. Unknown fields are ignored. */
public final class OsvSchema {

  private OsvSchema() {}

  public record Query(String ecosystem, String name, String version) {}

  public record Severity(String type, String score) {}

  public record Event(String introduced, String fixed, String lastAffected, String limit) {}

  public record Range(String type, List<Event> events) {}

  public record Affected(
      String ecosystem,
      String name,
      List<String> versions,
      List<Range> ranges,
      String databaseSpecific) {}

  public record Vuln(
      String id,
      List<String> aliases,
      String summary,
      String details,
      String published,
      String modified,
      boolean withdrawn,
      List<Severity> severities,
      List<Affected> affected,
      List<String> references) {}
}
