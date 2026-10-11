package dev.depfix.mcp.vuln;

import static org.junit.jupiter.api.Assertions.*;
import dev.depfix.mcp.model.DependencyRecord;
import java.util.List;
import org.junit.jupiter.api.Test;

class VersionMatcherTest {

  private static DependencyRecord rec(String eco, String name, String declared,
      String resolved, String kind, String type) {
    return new DependencyRecord(eco, name, declared, resolved, type, null, "f", kind, null);
  }

  private static DependencyRecord rec(String eco, String name, String declared,
      String resolved, String kind) {
    return rec(eco, name, declared, resolved, kind, null);
  }

  @Test
  void candidatePrefersResolvedOverConstraint() {
    var c = VersionMatcher.candidateFor(rec("npm", "react", "^19.0.0", "19.2.7", "lockfile"));
    assertTrue(c.isPresent());
    assertEquals("19.2.7", c.get().matchVersion());
    assertEquals("lockfile", c.get().versionSource());
    assertEquals("npm", c.get().osvEcosystem());
  }

  @Test
  void candidateAcceptsExactPinsAndGoMod() {
    var pip = VersionMatcher.candidateFor(rec("pip", "requests", "==2.28.1", null, "manifest"));
    assertTrue(pip.isPresent());
    assertEquals("2.28.1", pip.get().matchVersion());
    assertEquals("PyPI", pip.get().osvEcosystem());

    var go = VersionMatcher.candidateFor(rec("go", "github.com/spf13/cobra", "v1.8.0", "v1.8.0", "manifest"));
    assertTrue(go.isPresent());
    assertEquals("Go", go.get().osvEcosystem());
  }

  @Test
  void candidateRejectsRangesAndUnknownEcosystems() {
    assertTrue(VersionMatcher.candidateFor(rec("npm", "x", "^1.0.0", null, "manifest")).isEmpty());
    assertTrue(VersionMatcher.candidateFor(rec("maven", "g:a", null, null, "manifest")).isEmpty());
    assertTrue(VersionMatcher.candidateFor(rec("cargo", "x", "1.0.0", "1.0.0", "manifest")).isEmpty());

    var gradle = VersionMatcher.candidateFor(rec("gradle", "io.jsonwebtoken:jjwt-api", "0.12.6", null, "manifest"));
    assertTrue(gradle.isPresent());
    assertEquals("Maven", gradle.get().osvEcosystem());
  }

  @Test
  void semverOrdering() {
    assertTrue(VersionMatcher.compare("npm", "1.2.3", "1.2.4") < 0);
    assertTrue(VersionMatcher.compare("npm", "1.2.3", "1.2.3") == 0);
    assertTrue(VersionMatcher.compare("npm", "2.0.0", "10.0.0") < 0);
    assertTrue(VersionMatcher.compare("npm", "1.0.0-alpha", "1.0.0") < 0);
    assertTrue(VersionMatcher.compare("npm", "v1.8.0", "1.8.0") == 0);
  }

  @Test
  void mavenOrdering() {
    assertTrue(VersionMatcher.compare("Maven", "1.0-alpha", "1.0") < 0);
    assertTrue(VersionMatcher.compare("Maven", "1.0-SNAPSHOT", "1.0") < 0);
    assertTrue(VersionMatcher.compare("Maven", "1.0-rc1", "1.0") < 0);
    assertTrue(VersionMatcher.compare("Maven", "1.0", "1.0-sp1") < 0);
    assertTrue(VersionMatcher.compare("Maven", "6.1.0", "6.1.10") < 0);
    assertTrue(VersionMatcher.compare("Maven", "0.12.6", "0.12.6") == 0);
  }

  @Test
  void rangeIntroducedFixed() {
    var range = new OsvSchema.Range("ECOSYSTEM", List.of(
        new OsvSchema.Event("1.0.0", "1.2.0", null, null)));
    assertEquals(Boolean.TRUE, VersionMatcher.evaluateRange(range, "Maven", "1.1.0"));
    assertEquals(Boolean.FALSE, VersionMatcher.evaluateRange(range, "Maven", "1.2.0"));
    assertEquals(Boolean.FALSE, VersionMatcher.evaluateRange(range, "Maven", "0.9.0"));
  }

  @Test
  void rangeOpenEndedLimitAndLastAffected() {
    var open = new OsvSchema.Range("ECOSYSTEM", List.of(
        new OsvSchema.Event("2.0.0", null, null, null)));
    assertEquals(Boolean.TRUE, VersionMatcher.evaluateRange(open, "npm", "3.0.0"));
    assertEquals(Boolean.FALSE, VersionMatcher.evaluateRange(open, "npm", "1.9.0"));

    var last = new OsvSchema.Range("SEMVER", List.of(
        new OsvSchema.Event(null, null, "1.5.0", null)));
    assertEquals(Boolean.TRUE, VersionMatcher.evaluateRange(last, "npm", "1.5.0"));
    assertEquals(Boolean.FALSE, VersionMatcher.evaluateRange(last, "npm", "1.5.1"));

    var limit = new OsvSchema.Range("ECOSYSTEM", List.of(
        new OsvSchema.Event("1.0.0", null, null, "2.0.0")));
    assertEquals(Boolean.TRUE, VersionMatcher.evaluateRange(limit, "npm", "1.9.0"));
    assertEquals(Boolean.FALSE, VersionMatcher.evaluateRange(limit, "npm", "2.0.0"));
  }

  @Test
  void gitRangesAreUnevaluable() {
    var git = new OsvSchema.Range("GIT", List.of(
        new OsvSchema.Event("abc", "def", null, null)));
    assertNull(VersionMatcher.evaluateRange(git, "Go", "v1.0.0"));
  }

  @Test
  void confirmViaVersionsList() {
    var v = vuln("npm", "pkg", "PKG-1", List.of("1.0.0"), List.of());
    var hit = VersionMatcher.confirm(v, "npm", "pkg", "1.0.0");
    assertEquals(VersionMatcher.Verdict.CONFIRMED, hit.verdict());
    assertEquals("versions-list", hit.evidence());
    var miss = VersionMatcher.confirm(v, "npm", "pkg", "2.0.0");
    assertEquals(VersionMatcher.Verdict.NO_MATCH, miss.verdict());
  }

  @Test
  void confirmViaRangeAndLikelyFallback() {
    var ranged = vuln("npm", "pkg", "PKG-2", List.of(),
        List.of(new OsvSchema.Range("SEMVER", List.of(new OsvSchema.Event("0", "2.0.0", null, null)))));
    var hit = VersionMatcher.confirm(ranged, "npm", "pkg", "1.0.0");
    assertEquals(VersionMatcher.Verdict.CONFIRMED, hit.verdict());
    assertEquals("affected-range", hit.evidence());

    var git = vuln("Go", "example.com/m", "PKG-3", List.of(),
        List.of(new OsvSchema.Range("GIT", List.of(new OsvSchema.Event("a", "b", null, null)))));
    var likely = VersionMatcher.confirm(git, "Go", "example.com/m", "v1.0.0");
    assertEquals(VersionMatcher.Verdict.LIKELY, likely.verdict());
    assertEquals("server-indicated", likely.evidence());
  }

  @Test
  void confirmDropsIdentityMismatch() {
    var v = vuln("npm", "other-pkg", "PKG-4", List.of(),
        List.of(new OsvSchema.Range("SEMVER", List.of(new OsvSchema.Event("0", "9.9.9", null, null)))));
    var verdict = VersionMatcher.confirm(v, "npm", "pkg", "1.0.0");
    assertEquals(VersionMatcher.Verdict.NO_MATCH, verdict.verdict());
    assertEquals("identity-mismatch", verdict.evidence());
  }

  @Test
  void fixedVersionAndRangeText() {
    var v = vuln("Maven", "g:a", "PKG-5", List.of(),
        List.of(new OsvSchema.Range("ECOSYSTEM", List.of(
            new OsvSchema.Event("1.0.0", "1.2.0", null, null),
            new OsvSchema.Event("2.0.0", "2.1.0", null, null)))));
    assertEquals("1.2.0", VersionMatcher.fixedVersion(v, "Maven", "g:a").orElse(null));
    assertEquals(">=1.0.0, <1.2.0; >=2.0.0, <2.1.0",
        VersionMatcher.affectedRangeText(v, "Maven", "g:a").orElse(null));
  }

  @Test
  void cvssV3Scoring() {
    assertEquals(9.8, VersionMatcher.cvssV3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"));
    assertEquals(10.0, VersionMatcher.cvssV3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"));
    assertNull(VersionMatcher.cvssV3Score("not-a-vector"));
    assertNull(VersionMatcher.cvssV3Score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"));
    assertEquals("Critical", VersionMatcher.ratingFor(9.8));
    assertEquals("High", VersionMatcher.ratingFor(7.5));
    assertEquals("Medium", VersionMatcher.ratingFor(5.0));
    assertEquals("Low", VersionMatcher.ratingFor(0.1));
    assertEquals("unknown", VersionMatcher.ratingFor(null));
  }

  @Test
  void upgradeTypeAndRisk() {
    assertEquals("patch", VersionMatcher.upgradeTypeFor("npm", "7.18.1", "7.18.2"));
    assertEquals("minor", VersionMatcher.upgradeTypeFor("npm", "1.3.0", "1.4.0"));
    assertEquals("major", VersionMatcher.upgradeTypeFor("Maven", "3.3.15", "4.0.0"));
    assertEquals("unknown", VersionMatcher.upgradeTypeFor("npm", "1.0.0", null));
    assertEquals("unknown", VersionMatcher.upgradeTypeFor("npm", "abc", "1.0.0"));
    assertEquals("low", VersionMatcher.upgradeRiskFor("patch"));
    assertEquals("medium", VersionMatcher.upgradeRiskFor("minor"));
    assertEquals("high", VersionMatcher.upgradeRiskFor("major"));
    assertTrue(VersionMatcher.fixGuidanceFor("npm").contains("package.json"));
    assertTrue(VersionMatcher.fixGuidanceFor("go").contains("go get"));
  }

  @Test
  void relevanceMapping() {
    assertEquals("runtime", VersionMatcher.relevanceFor(rec("npm", "a", "1", "1", "lockfile", "production")));
    assertEquals("build-time", VersionMatcher.relevanceFor(rec("npm", "a", "1", "1", "lockfile", "development")));
    assertEquals("runtime", VersionMatcher.relevanceFor(rec("maven", "a", null, "1", "manifest", "compile")));
    assertEquals("build-time", VersionMatcher.relevanceFor(rec("maven", "a", null, "1", "manifest", "test")));
    assertEquals("build-time", VersionMatcher.relevanceFor(rec("gradle", "a", "1", null, "manifest", "testImplementation")));
    assertEquals("runtime", VersionMatcher.relevanceFor(rec("gradle", "a", "1", null, "manifest", "implementation")));
    assertEquals("runtime", VersionMatcher.relevanceFor(rec("go", "a", "1", "1", "manifest", null)));
    assertEquals("runtime", VersionMatcher.relevanceFor(rec("pip", "a", "==1", null, "manifest", null)));
    assertEquals("unknown", VersionMatcher.relevanceFor(rec("maven", "a", null, "1", "manifest", null)));
  }

  private static OsvSchema.Vuln vuln(String eco, String name, String id,
      List<String> versions, List<OsvSchema.Range> ranges) {
    return new OsvSchema.Vuln(id, List.of(), null, null, "2024-01-01T00:00:00Z", null, false,
        List.of(), List.of(new OsvSchema.Affected(eco, name, versions, ranges, null)), List.of());
  }
}
