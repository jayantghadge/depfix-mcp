package dev.depfix.mcp.service;

import dev.depfix.mcp.detector.DependencyFileDetector;
import dev.depfix.mcp.github.GitHubClient;
import dev.depfix.mcp.github.GitHubException;
import dev.depfix.mcp.model.AnalyzeResult;
import dev.depfix.mcp.model.DependencyRecord;
import dev.depfix.mcp.model.DetectedFile;
import dev.depfix.mcp.parser.DependencyAnalyzer;
import dev.depfix.mcp.parser.ParseOutcome;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class DependencyInventoryService {

  private final GitHubClient github;
  private final DependencyFileDetector detector;
  private final List<DependencyAnalyzer> analyzers;
  private final int maxFiles;
  private final long maxFileBytes;

  public DependencyInventoryService(
      GitHubClient github,
      DependencyFileDetector detector,
      List<DependencyAnalyzer> analyzers,
      @Value("${depfix.github.max-files:60}") int maxFiles,
      @Value("${depfix.github.max-file-bytes:1000000}") long maxFileBytes) {
    this.github = github;
    this.detector = detector;
    this.analyzers = analyzers;
    this.maxFiles = maxFiles;
    this.maxFileBytes = maxFileBytes;
  }

  public List<DetectedFile> detect(String owner, String repo, String branch, List<String> warnings) {
    List<String> tree = github.listTreePaths(owner, repo, branch);
    List<DetectedFile> files = detector.detect(tree);
    if (files.size() > maxFiles) {
      warnings.add("Detected " + files.size() + " dependency files; analyzing first " + maxFiles
          + " (bounded retrieval). Narrow the repository or split the analysis for full coverage.");
    }
    return files;
  }

  public AnalyzeResult analyze(String owner, String repo, String branch) {
    List<String> warnings = new ArrayList<>();
    List<String> limitations = new ArrayList<>(List.of(
        "Phase 1 stops at dependency inventory: no vulnerability matching, upgrades, or pull requests.",
        "Manifest constraints (e.g. ^4.2, >=1.0) are never reported as resolved versions.",
        "Transitive closure is not computed; direct/transitive is set only where the file format provides evidence.",
        "Target repository files are treated as untrusted data and never executed."));
    List<DetectedFile> detected;
    try {
      detected = detect(owner, repo, branch, warnings);
    } catch (GitHubException e) {
      return new AnalyzeResult(owner, repo, branch, Instant.now().toString(), List.of(), List.of(),
          Map.of(), Map.of(), warnings, limitations, e.getMessage());
    }

    List<DetectedFile> bounded = detected.stream().limit(maxFiles).toList();
    List<DependencyRecord> all = new ArrayList<>();
    for (DetectedFile f : bounded) {
      var analyzer = analyzers.stream().filter(a -> a.supports(f)).findFirst();
      if (analyzer.isEmpty()) {
        warnings.add(f.path() + ": " + (f.reason() == null ? "no parser available." : f.reason()));
        continue;
      }
      GitHubClient.FileContent fc;
      try {
        fc = github.fetchFile(owner, repo, f.path(), branch, maxFileBytes);
      } catch (GitHubException e) {
        warnings.add(f.path() + ": fetch failed (" + e.getMessage() + ").");
        continue;
      }
      if (fc.truncated()) {
        warnings.add(f.path() + ": file too large (" + fc.size()
            + " bytes > limit " + maxFileBytes + "); skipped, reported as detected but not analyzed.");
        continue;
      }
      try {
        ParseOutcome out = analyzer.get().analyze(f.path(), fc.content());
        all.addAll(out.dependencies());
        warnings.addAll(out.warnings());
      } catch (RuntimeException e) {
        warnings.add(f.path() + ": parser error (" + e.getMessage() + ").");
      }
    }

    // Deduplicate (ecosystem|name|declared|resolved|file|kind), keep stable order.
    LinkedHashSet<String> seen = new LinkedHashSet<>();
    List<DependencyRecord> deduped = new ArrayList<>();
    for (DependencyRecord d : all) {
      String key = String.join("|", n(d.ecosystem()), n(d.name()), n(d.declaredVersion()),
          n(d.resolvedVersion()), n(d.sourceFile()), n(d.sourceKind()));
      if (seen.add(key)) deduped.add(d);
    }
    deduped.sort(Comparator.comparing(DependencyRecord::ecosystem, Comparator.nullsLast(String::compareTo))
        .thenComparing(DependencyRecord::name, Comparator.nullsLast(String::compareTo))
        .thenComparing(DependencyRecord::sourceFile, Comparator.nullsLast(String::compareTo)));

    Map<String, Long> byEco = new TreeMap<>();
    Map<String, Long> byType = new TreeMap<>();
    for (DependencyRecord d : deduped) {
      byEco.merge(d.ecosystem() == null ? "unknown" : d.ecosystem(), 1L, Long::sum);
      byType.merge(d.dependencyType() == null ? "unspecified" : d.dependencyType(), 1L, Long::sum);
    }
    long supportedCount = bounded.stream().filter(DetectedFile::supported).count();
    if (supportedCount == 0 && !bounded.isEmpty()) {
      limitations.add("None of the detected files have a Phase-1 parser; result reports detection only.");
    }

    return new AnalyzeResult(owner, repo, branch, Instant.now().toString(), deduped, bounded,
        new LinkedHashMap<>(byEco), new LinkedHashMap<>(byType), warnings, limitations, null);
  }

  private static String n(String s) {
    return s == null ? "" : s;
  }
}
