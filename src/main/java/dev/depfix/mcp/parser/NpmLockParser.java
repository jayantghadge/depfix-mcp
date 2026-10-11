package dev.depfix.mcp.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.depfix.mcp.model.DependencyRecord;
import dev.depfix.mcp.model.DetectedFile;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Parses {@code package-lock.json} (v1 legacy {@code dependencies} and v2/v3
 * {@code packages}). Lockfile versions are concrete resolved versions; manifest
 * constraints are never inferred from them and vice versa.
 */
@Component
public class NpmLockParser implements DependencyAnalyzer {

  private final ObjectMapper mapper;

  public NpmLockParser(ObjectMapper mapper) {
    this.mapper = mapper;
  }

  @Override
  public boolean supports(DetectedFile file) {
    return "npm".equals(file.ecosystem()) && file.path().endsWith("package-lock.json");
  }

  @Override
  public ParseOutcome analyze(String path, String content) {
    List<DependencyRecord> deps = new ArrayList<>();
    List<String> warnings = new ArrayList<>();
    try {
      JsonNode root = mapper.readTree(content);
      int lockVersion = root.path("lockfileVersion").asInt(-1);
      boolean found = false;
      JsonNode packages = root.path("packages");
      if (packages.isObject() && !packages.isEmpty()) {
        Iterator<Map.Entry<String, JsonNode>> it = packages.fields();
        while (it.hasNext()) {
          var e = it.next();
          if (e.getKey().isBlank()) continue; // root entry
          String name = lockName(e.getKey());
          if (name == null) continue;
          JsonNode v = e.getValue();
          String version = v.path("version").asText(null);
          boolean dev = v.path("dev").asBoolean(false)
              || v.path("devOptional").asBoolean(false);
          deps.add(new DependencyRecord("npm", name, null, version,
              dev ? "development" : "production", null, path, "lockfile", null));
          found = true;
        }
      }
      JsonNode legacy = root.path("dependencies");
      if (!found && legacy.isObject()) {
        Iterator<Map.Entry<String, JsonNode>> it = legacy.fields();
        while (it.hasNext()) {
          var e = it.next();
          String version = e.getValue().path("version").asText(null);
          boolean dev = e.getValue().path("dev").asBoolean(false);
          deps.add(new DependencyRecord("npm", e.getKey(), null, version,
              dev ? "development" : "production", null, path, "lockfile", null));
          found = true;
        }
      }
      if (!found) {
        warnings.add(path + ": no packages/dependencies entries found (lockfileVersion=" + lockVersion + ").");
      } else if (lockVersion < 1 || lockVersion > 3) {
        warnings.add(path + ": unrecognized lockfileVersion=" + lockVersion + "; parsed best-effort.");
      }
    } catch (Exception e) {
      warnings.add(path + ": failed to parse package-lock.json (" + e.getMessage() + ").");
      return ParseOutcome.of(List.of(), warnings);
    }
    return ParseOutcome.of(deps, warnings);
  }

  private static String lockName(String key) {
    // keys like "node_modules/foo" or "node_modules/a/node_modules/b"
    int i = key.lastIndexOf("node_modules/");
    if (i < 0) return null;
    String name = key.substring(i + "node_modules/".length());
    return name.isBlank() ? null : name;
  }
}
