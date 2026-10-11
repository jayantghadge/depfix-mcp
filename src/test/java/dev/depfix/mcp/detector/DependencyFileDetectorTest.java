package dev.depfix.mcp.detector;

import static org.junit.jupiter.api.Assertions.*;
import dev.depfix.mcp.model.DetectedFile;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class DependencyFileDetectorTest {

  private final DependencyFileDetector detector = new DependencyFileDetector();

  @Test
  void detectsCoreAndMarksUnsupported() {
    List<DetectedFile> files = detector.detect(List.of(
        "pom.xml",
        "backend/build.gradle",
        "frontend/package.json",
        "frontend/package-lock.json",
        "frontend/yarn.lock",
        "req/requirements.txt",
        "pyproject.toml",
        "go.mod",
        "go.sum",
        "Cargo.toml",
        "README.md",
        "src/Main.java"));
    Map<String, DetectedFile> byPath =
        files.stream().collect(Collectors.toMap(DetectedFile::path, f -> f));

    assertTrue(byPath.get("pom.xml").supported());
    assertEquals("maven", byPath.get("pom.xml").ecosystem());
    assertTrue(byPath.get("frontend/package-lock.json").supported());
    assertEquals("lockfile", byPath.get("frontend/package-lock.json").fileRole());

    // Detected but not analyzed in Core-5 scope
    assertFalse(byPath.get("frontend/yarn.lock").supported());
    assertNotNull(byPath.get("frontend/yarn.lock").reason());
    assertFalse(byPath.get("go.sum").supported());
    assertTrue(byPath.get("go.sum").reason().toLowerCase().contains("checksum"));

    // Unknown files ignored
    assertFalse(byPath.containsKey("README.md"));
    assertFalse(byPath.containsKey("src/Main.java"));
  }

  @Test
  void csprojDetectedAsNugetUnsupported() {
    List<DetectedFile> files = detector.detect(List.of("src/App/App.csproj"));
    assertEquals(1, files.size());
    assertEquals("nuget", files.get(0).ecosystem());
    assertFalse(files.get(0).supported());
  }

  @Test
  void outputIsStablyOrdered() {
    List<DetectedFile> files = detector.detect(List.of("go.mod", "pom.xml", "package.json"));
    assertEquals(List.of("go.mod", "package.json", "pom.xml"),
        files.stream().map(DetectedFile::path).toList());
  }
}
