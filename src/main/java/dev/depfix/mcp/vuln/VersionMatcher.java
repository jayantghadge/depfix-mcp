package dev.depfix.mcp.vuln;

import dev.depfix.mcp.model.DependencyRecord;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Phase-2 version intelligence: selects a matchable version per inventory record,
 * compares versions with ecosystem-appropriate ordering, evaluates OSV affected
 * ranges locally, renders affected-range text, and scores CVSS v3 vectors.
 *
 * <p>Ordering is an approximation (notably Maven qualifiers); every finding
 * records its confidence and evidence so consumers can judge it. Nothing here
 * suggests upgrades — that belongs to a later phase.
 */
public final class VersionMatcher {

  private VersionMatcher() {}

  /** OSV ecosystem names for Phase-1 ecosystems. Gradle coordinates live in Maven. */
  private static final Map<String, String> OSV_ECOSYSTEM = Map.of(
      "maven", "Maven",
      "gradle", "Maven",
      "npm", "npm",
      "pip", "PyPI",
      "go", "Go");

  public record MatchCandidate(
      DependencyRecord record,
      String osvEcosystem,
      String osvName,
      String matchVersion,
      String versionSource) {}

  public enum Verdict { CONFIRMED, LIKELY, NO_MATCH }

  private static final Pattern PINNED = Pattern.compile(
      "^[v=\\s]*\\d+(\\.\\d+)*([-+._][0-9A-Za-z.-]+)?$");
  private static final Pattern EXACT_PIN = Pattern.compile("^={1,2}\\s*(.+)$");

  /** Picks the version to match, or empty when the record has nothing matchable. */
  public static Optional<MatchCandidate> candidateFor(DependencyRecord d) {
    String osvEco = OSV_ECOSYSTEM.get(d.ecosystem());
    if (osvEco == null || d.name() == null || d.name().isBlank()) {
      return Optional.empty();
    }
    if (d.resolvedVersion() != null && isPinned(d.resolvedVersion())) {
      String v = normalize(d.ecosystem(), d.resolvedVersion());
      String source = "lockfile".equals(d.sourceKind()) ? "lockfile"
          : "go".equals(d.ecosystem()) ? "go.mod" : "manifest";
      return Optional.of(new MatchCandidate(d, osvEco, d.name().strip(), v, source));
    }
    if (d.declaredVersion() != null) {
      String pin = toPin(d.declaredVersion());
      if (pin != null) {
        return Optional.of(new MatchCandidate(d, osvEco, d.name().strip(),
            normalize(d.ecosystem(), pin), "declared pin"));
      }
    }
    return Optional.empty();
  }

  /** Returns the pinned version if the constraint is an exact pin (==x.y.z), else null. */
  static String toPin(String constraint) {
    if (constraint == null) return null;
    Matcher m = EXACT_PIN.matcher(constraint.strip());
    String v = m.matches() ? m.group(1).strip() : constraint.strip();
    return isPinned(v) ? v.replaceAll("^[v=\\s]+", "") : null;
  }

  static boolean isPinned(String v) {
    if (v == null) return false;
    String s = v.strip();
    if (s.isEmpty()) return false;
    Matcher m = EXACT_PIN.matcher(s);
    if (m.matches()) s = m.group(1).strip();
    return PINNED.matcher(s).matches();
  }

  static String normalize(String ecosystem, String version) {
    String v = version.strip().replaceAll("^[v=\\s]+", "");
    if ("pip".equals(ecosystem)) {
      // Dots are significant in PEP 440; only case-fold here, OSV normalizes the rest.
      v = v.toLowerCase(Locale.ROOT);
    }
    return v;
  }

  // ---- comparison ----

  /** Compares versions for an OSV ecosystem (Maven/npm/Go/PyPI) or SEMVER ranges. */
  public static int compare(String osvEcosystem, String a, String b) {
    try {
      return switch (osvEcosystem) {
        case "Maven" -> compareMaven(a, b);
        case "npm", "Go", "SEMVER" -> compareSemver(a, b);
        default -> compareGeneric(a, b);
      };
    } catch (RuntimeException e) {
      return a.compareToIgnoreCase(b);
    }
  }

  static int compareSemver(String a, String b) {
    long[] na = semverCore(a);
    long[] nb = semverCore(b);
    for (int i = 0; i < 3; i++) {
      int c = Long.compare(na[i], nb[i]);
      if (c != 0) return c;
    }
    String pa = semverPre(a);
    String pb = semverPre(b);
    if (pa == null && pb == null) return 0;
    if (pa == null) return 1;
    if (pb == null) return -1;
    String[] ia = pa.split("\\.");
    String[] ib = pb.split("\\.");
    for (int i = 0; i < Math.max(ia.length, ib.length); i++) {
      if (i >= ia.length) return -1;
      if (i >= ib.length) return 1;
      boolean naNum = ia[i].matches("\\d+");
      boolean nbNum = ib[i].matches("\\d+");
      if (naNum && nbNum) {
        int c = Long.compare(Long.parseLong(ia[i]), Long.parseLong(ib[i]));
        if (c != 0) return c;
      } else if (naNum) {
        return -1;
      } else if (nbNum) {
        return 1;
      } else {
        int c = ia[i].compareTo(ib[i]);
        if (c != 0) return c;
      }
    }
    return 0;
  }

  private static long[] semverCore(String v) {
    String s = v.strip().replaceAll("^[v=\\s]+", "");
    int plus = s.indexOf('+');
    if (plus >= 0) s = s.substring(0, plus);
    int dash = s.indexOf('-');
    if (dash >= 0) s = s.substring(0, dash);
    String[] parts = s.split("\\.", -1);
    long[] out = {0, 0, 0};
    for (int i = 0; i < Math.min(3, parts.length); i++) {
      try {
        out[i] = Long.parseLong(parts[i]);
      } catch (NumberFormatException e) {
        out[i] = 0;
      }
    }
    return out;
  }

  private static String semverPre(String v) {
    String s = v.strip();
    int plus = s.indexOf('+');
    if (plus >= 0) s = s.substring(0, plus);
    int dash = s.indexOf('-');
    return dash >= 0 ? s.substring(dash + 1) : null;
  }

  /** Maven-like ordering approximation: numeric numerically, known qualifiers in
   * release order (alpha < beta < milestone < rc < snapshot < release < sp),
   * unknown qualifiers lexically after release. Case-insensitive. */
  static int compareMaven(String a, String b) {
    List<String> ta = mavenTokens(a);
    List<String> tb = mavenTokens(b);
    for (int i = 0; i < Math.max(ta.size(), tb.size()); i++) {
      String x = i < ta.size() ? ta.get(i) : "";
      String y = i < tb.size() ? tb.get(i) : "";
      int c = compareMavenToken(x, y);
      if (c != 0) return c;
    }
    return 0;
  }

  private static final Map<String, Integer> QUALIFIER_ORDER = Map.ofEntries(
      Map.entry("alpha", 1), Map.entry("a", 1),
      Map.entry("beta", 2), Map.entry("b", 2),
      Map.entry("milestone", 3), Map.entry("m", 3),
      Map.entry("rc", 4), Map.entry("cr", 4),
      Map.entry("snapshot", 5), Map.entry("snap", 5),
      Map.entry("", 6), Map.entry("ga", 6), Map.entry("final", 6), Map.entry("release", 6),
      Map.entry("sp", 7));

  private static int compareMavenToken(String x, String y) {
    boolean xn = x.matches("\\d+");
    boolean yn = y.matches("\\d+");
    if (xn && yn) {
      int c = Integer.compare(x.length(), y.length());
      if (c != 0) return c;
      return x.compareTo(y);
    }
    if (xn) return -1;
    if (yn) return 1;
    String xl = x.toLowerCase(Locale.ROOT);
    String yl = y.toLowerCase(Locale.ROOT);
    Integer xo = QUALIFIER_ORDER.get(xl);
    Integer yo = QUALIFIER_ORDER.get(yl);
    if (xo != null && yo != null) return Integer.compare(xo, yo);
    if (xo != null) return -1;
    if (yo != null) return 1;
    return xl.compareTo(yl);
  }

  private static List<String> mavenTokens(String v) {
    String s = v.strip().toLowerCase(Locale.ROOT).replaceAll("^[v=\\s]+", "");
    List<String> out = new ArrayList<>();
    StringBuilder cur = new StringBuilder();
    boolean curDigit = false;
    boolean started = false;
    for (char c : s.toCharArray()) {
      if (c == '.' || c == '-' || c == '_') {
        if (cur.length() > 0 || started) {
          out.add(cur.toString());
          cur.setLength(0);
        }
        started = true;
        continue;
      }
      boolean digit = Character.isDigit(c);
      if (started && cur.length() > 0 && digit != curDigit) {
        out.add(cur.toString());
        cur.setLength(0);
      }
      cur.append(c);
      curDigit = digit;
      started = true;
    }
    if (cur.length() > 0) out.add(cur.toString());
    return out;
  }

  /** Separator-insensitive fallback (PyPI and anything unknown). */
  static int compareGeneric(String a, String b) {
    List<String> ta = genericTokens(a);
    List<String> tb = genericTokens(b);
    for (int i = 0; i < Math.max(ta.size(), tb.size()); i++) {
      String x = i < ta.size() ? ta.get(i) : "";
      String y = i < tb.size() ? tb.get(i) : "";
      boolean xn = x.matches("\\d+");
      boolean yn = y.matches("\\d+");
      int c;
      if (xn && yn) {
        c = Integer.compare(x.length(), y.length());
        if (c == 0) c = x.compareTo(y);
      } else {
        c = x.compareToIgnoreCase(y);
      }
      if (c != 0) return c;
    }
    return 0;
  }

  private static List<String> genericTokens(String v) {
    List<String> out = new ArrayList<>();
    Matcher m = Pattern.compile("\\d+|[a-zA-Z]+").matcher(v);
    while (m.find()) out.add(m.group());
    return out;
  }

  // ---- confirmation ----

  public record Confirmation(Verdict verdict, String evidence) {}

  /**
   * Confirms a server-returned vuln: exact package identity plus local range or
   * versions-list match. CONFIRMED carries range/versions evidence; LIKELY means
   * OSV implicated it but ranges are not machine-evaluable; NO_MATCH drops it.
   */
  public static Confirmation confirm(OsvSchema.Vuln vuln, String osvEcosystem, String osvName, String version) {
    boolean identityMatched = false;
    boolean unevaluable = false;
    for (OsvSchema.Affected aff : vuln.affected()) {
      if (!aff.ecosystem().equalsIgnoreCase(osvEcosystem)
          || !aff.name().equalsIgnoreCase(osvName)) {
        continue;
      }
      identityMatched = true;
      if (!aff.versions().isEmpty()) {
        // A non-empty versions list is authoritative for what it contains.
        for (String listed : aff.versions()) {
          if (listed.equals(version) || normalizeLoose(listed).equals(normalizeLoose(version))) {
            return new Confirmation(Verdict.CONFIRMED, "versions-list");
          }
        }
        continue;
      }
      if (aff.ranges().isEmpty()) {
        unevaluable = true;
        continue;
      }
      for (OsvSchema.Range range : aff.ranges()) {
        Boolean hit = evaluateRange(range, osvEcosystem, version);
        if (hit == null) {
          unevaluable = true;
        } else if (hit) {
          return new Confirmation(Verdict.CONFIRMED, "affected-range");
        }
      }
    }
    if (!identityMatched) return new Confirmation(Verdict.NO_MATCH, "identity-mismatch");
    return unevaluable
        ? new Confirmation(Verdict.LIKELY, "server-indicated")
        : new Confirmation(Verdict.NO_MATCH, "outside-affected-ranges");
  }

  /** Evaluates one OSV range. Null when the range type is not version-evaluable. */
  static Boolean evaluateRange(OsvSchema.Range range, String osvEcosystem, String version) {
    String type = range.type();
    String comparator = "SEMVER".equalsIgnoreCase(type) ? "SEMVER"
        : "ECOSYSTEM".equalsIgnoreCase(type) ? osvEcosystem : null;
    if (comparator == null || range.events().isEmpty()) return null;
    String segmentStart = null; // null = from the beginning (affects all early versions)
    for (OsvSchema.Event e : range.events()) {
      if (e.introduced() != null) {
        segmentStart = e.introduced();
      }
      if (e.fixed() != null) {
        if (inSegment(comparator, segmentStart, version, e.fixed(), false)) return true;
        segmentStart = null;
      } else if (e.limit() != null) {
        if (inSegment(comparator, segmentStart, version, e.limit(), false)) return true;
        segmentStart = null;
      } else if (e.lastAffected() != null) {
        if (inSegment(comparator, segmentStart, version, e.lastAffected(), true)) return true;
        segmentStart = null;
      }
    }
    if (segmentStart != null) {
      return compare(comparator, version, segmentStart) >= 0;
    }
    return false;
  }

  private static boolean inSegment(String comparator, String start, String version,
      String end, boolean endInclusive) {
    if (start != null && compare(comparator, version, start) < 0) return false;
    int c = compare(comparator, version, end);
    return endInclusive ? c <= 0 : c < 0;
  }

  private static String normalizeLoose(String v) {
    return v.strip().replaceAll("^[v=\\s]+", "").toLowerCase(Locale.ROOT);
  }

  /** First published fixed version across machine-readable ranges, if any. */
  public static Optional<String> fixedVersion(OsvSchema.Vuln vuln, String osvEcosystem, String osvName) {
    for (OsvSchema.Affected aff : vuln.affected()) {
      if (!aff.ecosystem().equalsIgnoreCase(osvEcosystem)
          || !aff.name().equalsIgnoreCase(osvName)) {
        continue;
      }
      for (OsvSchema.Range range : aff.ranges()) {
        if (!"ECOSYSTEM".equalsIgnoreCase(range.type())
            && !"SEMVER".equalsIgnoreCase(range.type())) {
          continue;
        }
        for (OsvSchema.Event e : range.events()) {
          if (e.fixed() != null && !e.fixed().isBlank()) {
            return Optional.of(e.fixed());
          }
        }
      }
    }
    return Optional.empty();
  }

  /** Human-readable affected ranges for the report, e.g. ">=0, <1.3.1; >=2.0.0". */
  public static Optional<String> affectedRangeText(OsvSchema.Vuln vuln, String osvEcosystem, String osvName) {
    for (OsvSchema.Affected aff : vuln.affected()) {
      if (!aff.ecosystem().equalsIgnoreCase(osvEcosystem)
          || !aff.name().equalsIgnoreCase(osvName)) {
        continue;
      }
      List<String> segments = new ArrayList<>();
      for (OsvSchema.Range range : aff.ranges()) {
        if (!"ECOSYSTEM".equalsIgnoreCase(range.type())
            && !"SEMVER".equalsIgnoreCase(range.type())) {
          continue;
        }
        String start = null;
        for (OsvSchema.Event e : range.events()) {
          if (e.introduced() != null) start = e.introduced();
          if (e.fixed() != null) {
            segments.add((start == null ? "" : ">=" + start + ", ") + "<" + e.fixed());
            start = null;
          } else if (e.limit() != null) {
            segments.add((start == null ? "" : ">=" + start + ", ") + "<" + e.limit());
            start = null;
          } else if (e.lastAffected() != null) {
            segments.add((start == null ? "" : ">=" + start + ", ") + "<=" + e.lastAffected());
            start = null;
          }
        }
        if (start != null) segments.add(">=" + start);
      }
      if (!segments.isEmpty()) return Optional.of(String.join("; ", segments));
      if (!aff.versions().isEmpty()) {
        List<String> listed = aff.versions();
        String text = String.join(", ", listed.subList(0, Math.min(10, listed.size())));
        if (listed.size() > 10) text += ", …(+" + (listed.size() - 10) + " more)";
        return Optional.of("listed: " + text);
      }
    }
    return Optional.empty();
  }

  // ---- CVSS v3 ----

  /** CVSS v3.0/v3.1 base score from a vector string, or null when unparseable. */
  public static Double cvssV3Score(String vector) {
    try {
      if (vector == null || !vector.startsWith("CVSS:3.")) return null;
      Map<String, String> m = new java.util.HashMap<>();
      for (String part : vector.split("/")) {
        int i = part.indexOf(':');
        if (i > 0) m.put(part.substring(0, i), part.substring(i + 1));
      }
      double av = num(m.get("AV"), Map.of("N", 0.85, "A", 0.62, "L", 0.55, "P", 0.2));
      double ac = num(m.get("AC"), Map.of("L", 0.77, "H", 0.44));
      double pr = num(m.get("PR"), "C".equals(m.get("S"))
          ? Map.of("N", 0.85, "L", 0.68, "H", 0.5)
          : Map.of("N", 0.85, "L", 0.62, "H", 0.27));
      double ui = num(m.get("UI"), Map.of("N", 0.85, "R", 0.62));
      double c = num(m.get("C"), Map.of("H", 0.56, "L", 0.22, "N", 0.0));
      double integ = num(m.get("I"), Map.of("H", 0.56, "L", 0.22, "N", 0.0));
      double a = num(m.get("A"), Map.of("H", 0.56, "L", 0.22, "N", 0.0));
      double isc = 1.0 - (1 - c) * (1 - integ) * (1 - a);
      double impact;
      double expl = 8.22 * av * ac * pr * ui;
      if ("C".equals(m.get("S"))) {
        impact = 7.52 * (isc - 0.029) - 3.25 * Math.pow(isc - 0.029, 15);
      } else if ("U".equals(m.get("S"))) {
        impact = 6.42 * isc;
      } else {
        return null;
      }
      if (impact <= 0) return 0.0;
      double base = "C".equals(m.get("S"))
          ? Math.min(1.08 * (impact + expl), 10.0)
          : Math.min(impact + expl, 10.0);
      return roundup(base);
    } catch (RuntimeException e) {
      return null;
    }
  }

  private static double num(String key, Map<String, Double> table) {
    Double v = table.get(key);
    if (v == null) throw new IllegalArgumentException("Unknown CVSS metric value: " + key);
    return v;
  }

  private static double roundup(double input) {
    long scaled = (long) Math.ceil(input * 100000.0);
    return Math.ceil((scaled / 100000.0) * 10.0) / 10.0;
  }

  public static String ratingFor(Double score) {
    if (score == null) return "unknown";
    if (score >= 9.0) return "Critical";
    if (score >= 7.0) return "High";
    if (score >= 4.0) return "Medium";
    if (score > 0.0) return "Low";
    return "None";
  }

  /**
   * Upgrade distance between installed and target versions from the numeric
   * core: patch (low risk), minor (medium), major (high), unknown when either
   * side is not machine-readable. Qualifiers are stripped for the comparison.
   */
  public static String upgradeTypeFor(String osvEcosystem, String installed, String target) {
    try {
      if (installed == null || target == null) return "unknown";
      if (compare(osvEcosystem, target, installed) < 0) return "unknown";
      long[] a = numericCore(installed);
      long[] b = numericCore(target);
      if (a == null || b == null) return "unknown";
      if (b[0] != a[0]) return "major";
      if (b[1] != a[1]) return "minor";
      if (b[2] != a[2]) return "patch";
      return "patch";
    } catch (RuntimeException e) {
      return "unknown";
    }
  }

  private static long[] numericCore(String v) {
    if (v == null) return null;
    String s = v.strip().replaceAll("^[v=\\s]+", "");
    int cut = s.indexOf('-');
    if (cut >= 0) s = s.substring(0, cut);
    cut = s.indexOf('+');
    if (cut >= 0) s = s.substring(0, cut);
    String[] parts = s.split("\\.");
    if (parts.length == 0 || !parts[0].matches("\\d+")) return null;
    long[] out = {0, 0, 0};
    for (int i = 0; i < Math.min(3, parts.length); i++) {
      if (!parts[i].matches("\\d+")) return null;
      out[i] = Long.parseLong(parts[i]);
    }
    return out;
  }

  public static String upgradeRiskFor(String upgradeType) {
    return switch (upgradeType) {
      case "patch" -> "low";
      case "minor" -> "medium";
      case "major" -> "high";
      default -> "unknown";
    };
  }

  /** Where and how to apply the bump, per ecosystem. Advisory text, not commands. */
  public static String fixGuidanceFor(String ecosystem) {
    return switch (ecosystem) {
      case "npm" -> "Update the version constraint in package.json, regenerate the lockfile (npm install), and verify with npm ls <package>.";
      case "maven" -> "Update the <version> in pom.xml (or the referenced <properties> entry) and rebuild.";
      case "gradle" -> "Update the version in build.gradle(.kts) — direct string, ext/extra property, or version catalog — and resync.";
      case "go" -> "Run go get <module>@<version> followed by go mod tidy, then rebuild and retest.";
      case "pip" -> "Pin the exact version in requirements.txt (==<version>), reinstall, and retest.";
      default -> "Update the dependency declaration to the target version and rebuild.";
    };
  }

  /**
   * Runtime vs build-time relevance from the inventory's dependency scope.
   * Runtime = ships to / runs for users. Build-time = toolchains, test and
   * compile-only scopes. Unknown when the scope is missing.
   */
  public static String relevanceFor(DependencyRecord d) {
    String eco = d.ecosystem();
    String t = d.dependencyType();
    if ("npm".equals(eco)) {
      if ("production".equals(t) || "peer".equals(t) || "optional".equals(t)) return "runtime";
      if ("development".equals(t)) return "build-time";
      return "unknown";
    }
    if ("maven".equals(eco) || "gradle".equals(eco)) {
      if (t == null) return "unknown";
      String l = t.toLowerCase(Locale.ROOT);
      if (l.startsWith("test") || l.contains("compileonly") || l.contains("annotation")) {
        return "build-time";
      }
      return "runtime";
    }
    if ("go".equals(eco) || "pip".equals(eco)) return "runtime";
    return "unknown";
  }
}
