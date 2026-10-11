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

@Component
public class NpmManifestParser implements DependencyAnalyzer {

  private final ObjectMapper mapper;

  public NpmManifestParser(ObjectMapper mapper) {
    this.mapper = mapper;
  }

  @Override
  public boolean supports(DetectedFile file) {
    return "npm".equals(file.ecosystem()) && file.path().endsWith("package.json");
  }

  @Override
  public ParseOutcome analyze(String path, String content) {
    List<DependencyRecord> deps = new ArrayList<>();
    List<String> warnings = new ArrayList<>();
    try {
      JsonNode root = mapper.readTree(content);
      addAll(deps, root, path, "dependencies", "production");
      addAll(deps, root, path, "devDependencies", "development");
      addAll(deps, root, path, "peerDependencies", "peer");
      addAll(deps, root, path, "optionalDependencies", "optional");
      if (deps.isEmpty()) {
        warnings.add(path + ": no dependencies, devDependencies, peerDependencies, or optionalDependencies found.");
      }
    } catch (Exception e) {
      warnings.add(path + ": failed to parse package.json (" + e.getMessage() + ").");
      return ParseOutcome.of(List.of(), warnings);
    }
    return ParseOutcome.of(deps, warnings);
  }

  private void addAll(List<DependencyRecord> deps, JsonNode root, String path,
      String field, String type) {
    JsonNode node = root.path(field);
    if (!node.isObject()) return;
    Iterator<Map.Entry<String, JsonNode>> it = node.fields();
    while (it.hasNext()) {
      var e = it.next();
      String constraint = e.getValue().isTextual() ? e.getValue().asText() : e.getValue().toString();
      deps.add(new DependencyRecord("npm", e.getKey(), constraint, null, type,
          "direct", path, "manifest", null));
    }
  }
}
