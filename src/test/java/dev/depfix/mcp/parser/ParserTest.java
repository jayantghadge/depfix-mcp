package dev.depfix.mcp.parser;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.depfix.mcp.model.DetectedFile;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class ParserTest {

  private static String fixture(String p) throws Exception {
    return Files.readString(Path.of("src/test/resources/fixtures", p));
  }

  private static DetectedFile f(String path, String eco) {
    return new DetectedFile(path, eco, "manifest", true, null);
  }

  @Test
  void mavenResolvesPropertiesAndSkipsManaged() throws Exception {
    var parser = new MavenPomParser();
    var out = parser.analyze("pom.xml", fixture("maven/pom.xml"));
    var byName = names(out);
    assertTrue(byName.contains("org.springframework:spring-core"));
    assertTrue(byName.contains("com.fasterxml.jackson.core:jackson-databind"));
    // dependencyManagement-only versions are not separate records, but a <dependencies>
    // entry without <version> IS a declared dep with an externally-managed version.
    assertTrue(byName.contains("com.example:managed-only"));
    var managed = out.dependencies().stream()
        .filter(d -> d.name().equals("com.example:managed-only")).findFirst().orElseThrow();
    assertNull(managed.declaredVersion());
    assertNull(managed.resolvedVersion());
    var spring = out.dependencies().stream()
        .filter(d -> d.name().equals("org.springframework:spring-core")).findFirst().orElseThrow();
    assertEquals("6.1.0", spring.declaredVersion());
    assertNull(spring.resolvedVersion());
    assertEquals("compile", spring.dependencyType());
    assertEquals("direct", spring.directOrTransitive());
    // unresolved property flagged, no version recorded as resolved
    var un = out.dependencies().stream()
        .filter(d -> d.name().equals("com.example:unresolved-prop")).findFirst().orElseThrow();
    assertNotNull(un.parseStatus());
  }

  @Test
  void mavenMalformedProducesWarningNotThrow() {
    var parser = new MavenPomParser();
    var out = parser.analyze("pom.xml", "not xml <<<");
    assertTrue(out.dependencies().isEmpty());
    assertFalse(out.warnings().isEmpty());
  }

  @Test
  void npmManifestKeepsConstraintsDistinctFromResolved() throws Exception {
    var parser = new NpmManifestParser(new ObjectMapper());
    var out = parser.analyze("package.json", fixture("npm/package.json"));
    assertEquals(5, out.dependencies().size());
    var express = out.dependencies().stream().filter(d -> d.name().equals("express")).findFirst().orElseThrow();
    assertEquals("^4.18.2", express.declaredVersion());
    assertNull(express.resolvedVersion()); // constraint must not become a resolved version
    assertEquals("production", express.dependencyType());
    var jest = out.dependencies().stream().filter(d -> d.name().equals("jest")).findFirst().orElseThrow();
    assertEquals("development", jest.dependencyType());
  }

  @Test
  void npmLockPrefersResolvedVersions() throws Exception {
    var parser = new NpmLockParser(new ObjectMapper());
    var out = parser.analyze("package-lock.json", fixture("npm/package-lock.json"));
    var express = out.dependencies().stream().filter(d -> d.name().equals("express")).findFirst().orElseThrow();
    assertEquals("4.18.2", express.resolvedVersion());
    assertNull(express.declaredVersion());
    assertEquals("lockfile", express.sourceKind());
    var jest = out.dependencies().stream().filter(d -> d.name().equals("jest")).findFirst().orElseThrow();
    assertEquals("development", jest.dependencyType());
  }

  @Test
  void pipParsesConstraintsAndFlagsUnsupported() throws Exception {
    var parser = new PipRequirementsParser();
    var out = parser.analyze("requirements.txt", fixture("pip/requirements.txt"));
    var byName = names(out);
    assertTrue(byName.contains("requests"));
    assertTrue(byName.contains("flask"));
    var requests = out.dependencies().stream().filter(d -> d.name().equals("requests")).findFirst().orElseThrow();
    assertEquals("==2.28.1", requests.declaredVersion());
    assertNull(requests.resolvedVersion()); // manifest constraint is not a resolved version
    // warnings for include, option, editable, garbage line
    assertTrue(out.warnings().size() >= 3);
  }

  @Test
  void gradleParsesLiteralsAndFlagsCatalogs() throws Exception {
    var parser = new GradleParser();
    var out = parser.analyze("build.gradle", fixture("gradle/build.gradle"));
    var byName = names(out);
    assertTrue(byName.contains("org.springframework:spring-core"));
    assertTrue(byName.contains("org.projectlombok:lombok"));
    // catalog ref reported with unresolved status + warning
    assertTrue(out.warnings().stream().anyMatch(w -> w.contains("libs.spring.boot.starter")));
    // dynamic version reported as-is
    var dyn = out.dependencies().stream()
        .filter(d -> d.name().equals("com.example:dynamic")).findFirst().orElseThrow();
    assertEquals("+", dyn.declaredVersion());
  }

  @Test
  void goModMarksDirectVsIndirect() throws Exception {
    var parser = new GoModParser();
    var out = parser.analyze("go.mod", fixture("go/go.mod"));
    var cobra = out.dependencies().stream()
        .filter(d -> d.name().equals("github.com/spf13/cobra")).findFirst().orElseThrow();
    assertEquals("direct", cobra.directOrTransitive());
    var yaml = out.dependencies().stream()
        .filter(d -> d.name().equals("gopkg.in/yaml.v3")).findFirst().orElseThrow();
    assertEquals("transitive", yaml.directOrTransitive());
  }

  private static java.util.Set<String> names(ParseOutcome out) {
    return out.dependencies().stream().map(d -> d.name())
        .collect(java.util.stream.Collectors.toSet());
  }
}
