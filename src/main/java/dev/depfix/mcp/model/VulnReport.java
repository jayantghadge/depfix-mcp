package dev.depfix.mcp.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record VulnReport(
    String owner,
    String repo,
    String branch,
    String assessedAt,
    int dependenciesAssessed,
    Map<String, Long> assessedByEcosystem,
    Map<String, Long> skippedByEcosystem,
    int vulnerablePackages,
    int totalFindings,
    Map<String, Long> findingsByUrgency,
    Map<String, Long> findingsByRating,
    Map<String, String> sources,
    List<VulnFinding> findings,
    List<Remediation> remediations,
    List<SkippedDependency> skipped,
    List<String> warnings,
    List<String> limitations,
    String error) {}
