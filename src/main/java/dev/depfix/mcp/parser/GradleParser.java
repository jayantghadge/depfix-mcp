package dev.depfix.mcp.parser;

import dev.depfix.mcp.model.DependencyRecord;
import dev.depfix.mcp.model.DetectedFile;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * Best-effort Gradle parser (Groovy + Kotlin DSL) for string-literal dependency
 * declarations. Resolves version references ({@code $var} / {@code ${var}}) against
 * {@code ext { }} / {@code ext.var = ...} (Groovy) and {@code extra["var"] = ...}
 * (Kotlin DSL) assignments found in the same file — pure text parsing, the build
 * is never executed. Version catalogs ({@code libs.*}), dynamic expressions,
 * platform constraints, and applied scripts are reported as limitations.
 */
@Component
public class GradleParser implements DependencyAnalyzer {

  // implementation("group:name:1.0") | implementation 'group:name:1.0' | implementation(group='..', name='..', version='..')
  private static final Pattern STRING_DEP = Pattern.compile(
      "(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|"
          + "developmentOnly|annotationProcessor|testCompileOnly|debugImplementation|releaseImplementation)"
          + "\\s*\\(?\\s*[\"']([^\"']+)[\"']\\s*\\)?");
  private static final Pattern CATALOG_DEP = Pattern.compile(
      "(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|"
          + "developmentOnly|annotationProcessor)\\s*\\(?\\s*(libs\\.[A-Za-z0-9_.-]+)\\s*\\)?");
  private static final Pattern MAP_DEP = Pattern.compile(
      "(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)"
          + "\\s*\\(?\\s*group\\s*[:=]\\s*[\"']([^\"']+)[\"']\\s*,\\s*name\\s*[:=]\\s*[\"']([^\"']+)[\"']"
          + "\\s*(,\\s*version\\s*[:=]\\s*[\"']([^\"']+)[\"'])?");

  // ext { jjwtVersion = "0.12.6" }  |  project.ext { ... }
  private static final Pattern EXT_BLOCK_OPEN =
      Pattern.compile("(?m)^\\s*(?:project\\s*\\.\\s*)?ext\\s*\\{");
  // name = "value"  (inside an ext block)
  private static final Pattern EXT_ASSIGN =
      Pattern.compile("(?m)^\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*[\"']([^\"']*)[\"']");
  // ext.jjwtVersion = "0.12.6"
  private static final Pattern EXT_DOT_ASSIGN = Pattern.compile(
      "(?:project\\s*\\.\\s*)?ext\\.([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*[\"']([^\"']*)[\"']");
  // extra["jjwtVersion"] = "0.12.6"  (Kotlin DSL)
  private static final Pattern KOTLIN_EXTRA_SET = Pattern.compile(
      "extra\\s*\\[\\s*\"([^\"]+)\"\\s*\\]\\s*=\\s*\"([^\"]*)\"");
  // $var or ${var} (whole version string)
  private static final Pattern VERSION_REF =
      Pattern.compile("^\\$\\{?([A-Za-z_][A-Za-z0-9_.]*)\\}?$");

  @Override
  public boolean supports(DetectedFile file) {
    return "gradle".equals(file.ecosystem())
        && (file.path().endsWith("build.gradle") || file.path().endsWith("build.gradle.kts"));
  }

  @Override
  public ParseOutcome analyze(String path, String content) {
    List<DependencyRecord> deps = new ArrayList<>();
    List<String> warnings = new ArrayList<>();
    Map<String, String> ext = extractExtProperties(content);

    Matcher mm = MAP_DEP.matcher(content);
    while (mm.find()) {
      String conf = mm.group(1);
      String name = mm.group(2) + ":" + mm.group(3);
      String version = mm.group(5);
      deps.add(record(conf, name, version, path, ext, warnings));
    }
    String withoutMaps = mm.replaceAll("");

    Matcher sm = STRING_DEP.matcher(withoutMaps);
    while (sm.find()) {
      String conf = sm.group(1);
      String coords = sm.group(2).strip();
      if (coords.startsWith("libs.") || coords.startsWith("projects.")) {
        warnings.add(path + ": version-catalog/project reference '" + coords + "' not resolved in Phase 1.");
        deps.add(new DependencyRecord("gradle", coords, null, null, conf,
            "direct", path, "manifest", "version catalog reference; version unresolved"));
        continue;
      }
      String[] parts = coords.split(":");
      if (parts.length == 3) {
        deps.add(record(conf, parts[0] + ":" + parts[1], parts[2], path, ext, warnings));
      } else if (parts.length == 2) {
        warnings.add(path + ": dependency '" + coords + "' has no version; not resolved in Phase 1.");
        deps.add(new DependencyRecord("gradle", coords, null, null, conf,
            "direct", path, "manifest", "no version declared"));
      } else {
        warnings.add(path + ": dynamic expression '" + coords + "' not evaluated (build files are never executed).");
        deps.add(new DependencyRecord("gradle", coords, null, null, conf,
            "direct", path, "manifest", "dynamic expression; not evaluated"));
      }
    }

    Matcher cm = CATALOG_DEP.matcher(withoutMaps);
    while (cm.find()) {
      warnings.add(path + ": version-catalog reference '" + cm.group(2) + "' not resolved in Phase 1.");
      deps.add(new DependencyRecord("gradle", cm.group(2), null, null, cm.group(1),
          "direct", path, "manifest", "version catalog reference; version unresolved"));
    }

    if (content.contains("versionCatalogs") || content.contains("libs.versions.toml")) {
      warnings.add(path + ": version catalogs (libs.versions.toml) are not resolved in Phase 1.");
    }
    if (deps.isEmpty() && warnings.isEmpty()) {
      warnings.add(path + ": no supported dependency declarations found. Dynamic/Kotlin expressions may need manual review.");
    }
    return ParseOutcome.of(deps, warnings);
  }

  private DependencyRecord record(String conf, String name, String version, String path,
      Map<String, String> ext, List<String> warnings) {
    String status = null;
    String declared = version;
    if (version != null) {
      Matcher ref = VERSION_REF.matcher(version.strip());
      if (ref.matches()) {
        String key = ref.group(1);
        String resolved = ext.get(key);
        if (resolved == null && key.contains(".")) {
          resolved = ext.get(key.substring(key.lastIndexOf('.') + 1));
        }
        if (resolved != null) {
          declared = resolved;
          status = "version property '" + key + "' resolved from ext/extra block";
        } else {
          warnings.add(path + ": version property '" + key + "' for " + name
              + " not found in ext/extra block; version unresolved.");
          status = "unresolved version property '" + key + "'";
        }
      } else if (isDynamic(version)) {
        status = "dynamic version '" + version + "' reported as-is; not resolved";
      }
    }
    return new DependencyRecord("gradle", name, declared, null, conf, "direct", path, "manifest", status);
  }

  private static boolean isDynamic(String version) {
    return version.endsWith("+") || version.startsWith("latest")
        || version.startsWith("prefix") || version.contains("[") || version.contains("(");
  }

  /**
   * Collects {@code ext} / {@code extra} version properties by pure text scanning.
   * Only single-level quoted assignments are recognized; anything else keeps the
   * reference unresolved with a warning at the use site.
   */
  static Map<String, String> extractExtProperties(String content) {
    Map<String, String> props = new LinkedHashMap<>();
    Matcher open = EXT_BLOCK_OPEN.matcher(content);
    while (open.find()) {
      int depth = 0;
      int end = -1;
      for (int i = open.end() - 1; i < content.length(); i++) {
        char c = content.charAt(i);
        if (c == '{') depth++;
        else if (c == '}') {
          depth--;
          if (depth == 0) {
            end = i;
            break;
          }
        }
      }
      if (end > 0) {
        Matcher assign = EXT_ASSIGN.matcher(content.substring(open.end(), end));
        while (assign.find()) {
          props.putIfAbsent(assign.group(1), assign.group(2));
        }
      }
    }
    Matcher dot = EXT_DOT_ASSIGN.matcher(content);
    while (dot.find()) {
      props.putIfAbsent(dot.group(1), dot.group(2));
    }
    Matcher extra = KOTLIN_EXTRA_SET.matcher(content);
    while (extra.find()) {
      props.putIfAbsent(extra.group(1), extra.group(2));
    }
    return props;
  }
}
