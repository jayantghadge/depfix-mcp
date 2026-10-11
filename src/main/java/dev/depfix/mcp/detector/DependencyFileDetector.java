package dev.depfix.mcp.detector;

import dev.depfix.mcp.model.DetectedFile;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Detects candidate dependency files from repository tree paths.
 *
 * <p>Detection and extraction are separate: every known file is reported, but only formats
 * with an implemented Phase-1 parser are marked {@code supported=true}. Everything else
 * carries an explicit reason so it is never silently skipped.
 */
@Component
public class DependencyFileDetector {

  public List<DetectedFile> detect(List<String> treePaths) {
    List<DetectedFile> out = new ArrayList<>();
    for (String path : treePaths) {
      DetectedFile f = classify(path);
      if (f != null) out.add(f);
    }
    out.sort((a, b) -> a.path().compareTo(b.path()));
    return out;
  }

  private DetectedFile classify(String path) {
    String file = base(path);
    return switch (file) {
      case "pom.xml" -> sup(path, "maven", "manifest");
      case "build.gradle", "build.gradle.kts" -> sup(path, "gradle", "manifest");
      case "package.json" -> sup(path, "npm", "manifest");
      case "package-lock.json" -> sup(path, "npm", "lockfile");
      case "requirements.txt" -> sup(path, "pip", "manifest");
      case "go.mod" -> sup(path, "go", "manifest");
      case "yarn.lock" -> unsup(path, "yarn", "lockfile",
          "Detected but not analyzed in Phase 1 (Core-5 scope covers npm package.json/package-lock.json only).");
      case "pnpm-lock.yaml" -> unsup(path, "pnpm", "lockfile",
          "Detected but not analyzed in Phase 1 (Core-5 scope covers npm package.json/package-lock.json only).");
      case "pyproject.toml" -> unsup(path, "python", "manifest",
          "Detected but not analyzed in Phase 1 (Core-5 pip scope covers requirements.txt only).");
      case "poetry.lock" -> unsup(path, "poetry", "lockfile",
          "Detected but not analyzed in Phase 1.");
      case "Pipfile" -> unsup(path, "pipenv", "manifest", "Detected but not analyzed in Phase 1.");
      case "Pipfile.lock" -> unsup(path, "pipenv", "lockfile", "Detected but not analyzed in Phase 1.");
      case "go.sum" -> unsup(path, "go", "lockfile",
          "Detected but not analyzed: go.sum holds checksums only, not a dependency graph.");
      case "Cargo.toml", "Cargo.lock" -> unsup(path, "cargo", lockOrManifest(file),
          "Detected but not analyzed in Phase 1 (Core-5 scope).");
      case "composer.json", "composer.lock" -> unsup(path, "composer", lockOrManifest(file),
          "Detected but not analyzed in Phase 1 (Core-5 scope).");
      case "Gemfile", "Gemfile.lock" -> unsup(path, "bundler", lockOrManifest(file),
          "Detected but not analyzed in Phase 1 (Core-5 scope).");
      case "packages.lock.json" -> unsup(path, "nuget", "lockfile",
          "Detected but not analyzed in Phase 1 (Core-5 scope).");
      default -> {
        if (file.endsWith(".csproj")) {
          yield unsup(path, "nuget", "manifest", "Detected but not analyzed in Phase 1 (Core-5 scope).");
        }
        yield null;
      }
    };
  }

  private static DetectedFile sup(String path, String eco, String role) {
    return new DetectedFile(path, eco, role, true, null);
  }

  private static DetectedFile unsup(String path, String eco, String role, String reason) {
    return new DetectedFile(path, eco, role, false, reason);
  }

  private static String lockOrManifest(String file) {
    return file.contains("lock") ? "lockfile" : "manifest";
  }

  private static String base(String path) {
    int i = path.lastIndexOf('/');
    return i < 0 ? path : path.substring(i + 1);
  }
}
