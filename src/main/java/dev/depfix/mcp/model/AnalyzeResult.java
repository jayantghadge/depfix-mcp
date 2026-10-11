package dev.depfix.mcp.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record AnalyzeResult(
    String owner,
    String repo,
    String branch,
    String analyzedAt,
    List<DependencyRecord> dependencies,
    List<DetectedFile> detectedFiles,
    Map<String, Long> summaryByEcosystem,
    Map<String, Long> summaryByType,
    List<String> warnings,
    List<String> limitations,
    String error) {}
