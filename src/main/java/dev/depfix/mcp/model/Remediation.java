package dev.depfix.mcp.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record Remediation(
    int priority,
    String packageName,
    String ecosystem,
    String installedVersion,
    String targetVersion,
    String upgradeType,
    String upgradeRisk,
    String urgency,
    String relevance,
    List<String> vulnIds,
    List<String> cves,
    List<String> unfixedVulns,
    List<String> sourceFiles,
    String fixGuidance) {}
