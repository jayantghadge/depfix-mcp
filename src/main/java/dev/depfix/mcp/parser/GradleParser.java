package dev.depfix.mcp.parser;

import dev.depfix.mcp.model.DependencyRecord;
import dev.depfix.mcp.model.DetectedFile;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * Best-effort Gradle parser (Groovy + Kotlin DSL) for string-literal dependency
 * declarations. Version catalogs ({@code libs.*}), dynamic expressions, platform
 * constraints, and applied scripts are reported as limitations — never silently resolved.
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

  @Override
  public boolean supports(DetectedFile file) {
    return "gradle".equals(file.ecosystem())
        && (file.path().endsWith("build.gradle") || file.path().endsWith("build.gradle.kts"));
  }

  @Override
  public ParseOutcome analyze(String path, String content) {
    List<DependencyRecord> deps = new ArrayList<>();
    List<String> warnings = new ArrayList<>();

    Matcher mm = MAP_DEP.matcher(content);
    while (mm.find()) {
      String conf = mm.group(1);
      String name = mm.group(2) + ":" + mm.group(3);
      String version = mm.group(5);
      deps.add(record(conf, name, version, path));
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
        deps.add(record(conf, parts[0] + ":" + parts[1], parts[2], path));
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

  private static DependencyRecord record(String conf, String name, String version, String path) {
    String status = null;
    if (version != null && (version.endsWith("+") || version.startsWith("latest")
        || version.startsWith("prefix") || version.contains("[") || version.contains("("))) {
      status = "dynamic version '" + version + "' reported as-is; not resolved";
    }
    return new DependencyRecord("gradle", name, version, null, conf, "direct", path, "manifest", status);
  }
}
