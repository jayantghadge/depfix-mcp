package dev.depfix.mcp.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record VulnFinding(
    String ecosystem,
    String packageName,
    String installedVersion,
    String versionSource,
    String sourceFile,
    String relevance,
    String vulnId,
    List<String> aliases,
    String title,
    Double severityScore,
    String severityRating,
    String severityVector,
    String severitySource,
    String fixedVersion,
    String affectedRanges,
    String published,
    boolean kevListed,
    String kevDueDate,
    String kevRequiredAction,
    String confidence,
    String urgency,
    String matchEvidence,
    String osvUrl,
    List<String> references) {}
