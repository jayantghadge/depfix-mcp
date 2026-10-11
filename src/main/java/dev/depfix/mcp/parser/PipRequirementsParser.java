package dev.depfix.mcp.parser;

import dev.depfix.mcp.model.DependencyRecord;
import dev.depfix.mcp.model.DetectedFile;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * Parses pip {@code requirements.txt}. Keeps declared constraints distinct from resolved
 * versions (resolved stays null: a manifest is not a lockfile). Flags unsupported forms
 * (includes, options, editable installs, unparseable lines) as warnings.
 */
@Component
public class PipRequirementsParser implements DependencyAnalyzer {

  private static final Pattern LINE =
      Pattern.compile("^([A-Za-z0-9_.\\-]+(\\[[^\\]]+\\])?)\\s*(.*)$");

  @Override
  public boolean supports(DetectedFile file) {
    return "pip".equals(file.ecosystem()) && file.path().endsWith("requirements.txt");
  }

  @Override
  public ParseOutcome analyze(String path, String content) {
    List<DependencyRecord> deps = new ArrayList<>();
    List<String> warnings = new ArrayList<>();
    String[] lines = content.split("\\R");
    for (int ln = 0; ln < lines.length; ln++) {
      String raw = lines[ln].strip();
      if (raw.isEmpty() || raw.startsWith("#")) continue;
      String code = stripInlineComment(raw).strip();
      if (code.isEmpty()) continue;
      if (code.startsWith("-r ") || code.startsWith("--requirement")
          || code.startsWith("-c ") || code.startsWith("--constraint")) {
        warnings.add(path + ":" + (ln + 1) + ": nested include '" + code + "' not followed in Phase 1.");
        continue;
      }
      if (code.startsWith("-") || code.startsWith("--")) {
        warnings.add(path + ":" + (ln + 1) + ": pip option '" + code + "' ignored (not a dependency).");
        continue;
      }
      if (code.startsWith("-e ") || code.startsWith("--editable")) {
        warnings.add(path + ":" + (ln + 1) + ": editable install '" + code + "' recorded best-effort.");
        deps.add(new DependencyRecord("pip", code, null, null, null,
            "direct", path, "manifest", "editable install; version not parsed"));
        continue;
      }
      Matcher m = LINE.matcher(code);
      if (!m.matches()) {
        warnings.add(path + ":" + (ln + 1) + ": unsupported requirement syntax, skipped: '" + raw + "'.");
        continue;
      }
      String name = m.group(1);
      String rest = m.group(3) == null ? "" : m.group(3).strip();
      // Split off environment markers: pkg ... ; python_version > "3"
      String constraint = rest;
      String status = null;
      int sc = rest.indexOf(';');
      if (sc >= 0) {
        constraint = rest.substring(0, sc).strip();
        status = "environment markers: " + rest.substring(sc + 1).strip();
      }
      if (constraint.isEmpty()) constraint = null;
      else if (!constraint.matches("^(==|>=|<=|~=|!=|>|<|===).*") && !constraint.matches("^[0-9].*")) {
        warnings.add(path + ":" + (ln + 1) + ": unusual constraint for " + name + ": '" + constraint + "'.");
      }
      deps.add(new DependencyRecord("pip", name, constraint, null, null,
          "direct", path, "manifest", status));
    }
    if (deps.isEmpty() && warnings.isEmpty()) {
      warnings.add(path + ": no dependencies found.");
    }
    return ParseOutcome.of(deps, warnings);
  }

  private static String stripInlineComment(String line) {
    // Cut at ' #' (space-hash) to avoid breaking URLs/eggs containing '#'.
    int i = line.indexOf(" #");
    if (i >= 0) return line.substring(0, i);
    if (line.startsWith("#")) return "";
    return line;
  }
}
