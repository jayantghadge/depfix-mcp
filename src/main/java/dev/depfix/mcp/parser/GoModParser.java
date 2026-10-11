package dev.depfix.mcp.parser;

import dev.depfix.mcp.model.DependencyRecord;
import dev.depfix.mcp.model.DetectedFile;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/** Parses Go {@code go.mod}: module requirements, versions, direct vs indirect. */
@Component
public class GoModParser implements DependencyAnalyzer {

  private static final Pattern SINGLE_REQUIRE =
      Pattern.compile("^require\\s+(\\S+)\\s+(\\S+)(\\s*//\\s*indirect)?\\s*$");
  private static final Pattern BLOCK_ENTRY =
      Pattern.compile("^(\\S+)\\s+(\\S+)(\\s*//\\s*indirect)?\\s*$");

  @Override
  public boolean supports(DetectedFile file) {
    return "go".equals(file.ecosystem()) && file.path().endsWith("go.mod");
  }

  @Override
  public ParseOutcome analyze(String path, String content) {
    List<DependencyRecord> deps = new ArrayList<>();
    List<String> warnings = new ArrayList<>();
    boolean inRequire = false;
    String[] lines = content.split("\\R");
    for (int ln = 0; ln < lines.length; ln++) {
      String line = lines[ln].strip();
      if (line.isEmpty() || line.startsWith("//")) continue;
      if (line.startsWith("require (")) {
        inRequire = true;
        continue;
      }
      if (inRequire && line.equals(")")) {
        inRequire = false;
        continue;
      }
      if (inRequire) {
        Matcher m = BLOCK_ENTRY.matcher(line);
        if (m.matches()) {
          deps.add(goRecord(m.group(1), m.group(2), m.group(3) != null, path));
        } else {
          warnings.add(path + ":" + (ln + 1) + ": unrecognized require entry, skipped: '" + line + "'.");
        }
        continue;
      }
      Matcher s = SINGLE_REQUIRE.matcher(line);
      if (s.matches()) {
        deps.add(goRecord(s.group(1), s.group(2), s.group(3) != null, path));
      } else if (line.startsWith("replace ") || line.startsWith("retract ")) {
        warnings.add(path + ":" + (ln + 1) + ": '" + line.split("\\s+")[0]
            + "' directives are noted but do not change the reported versions in Phase 1.");
      }
    }
    if (deps.isEmpty() && warnings.isEmpty()) {
      warnings.add(path + ": no require directives found.");
    }
    return ParseOutcome.of(deps, warnings);
  }

  private static DependencyRecord goRecord(String module, String version, boolean indirect, String path) {
    // go.mod pins minimum versions: report as both declared and resolved with a note.
    return new DependencyRecord("go", module, version, version, null,
        indirect ? "transitive" : "direct", path, "manifest",
        "go.mod minimum version; full module graph not resolved");
  }
}
