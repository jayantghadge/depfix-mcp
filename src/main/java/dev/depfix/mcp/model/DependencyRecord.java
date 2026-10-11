package dev.depfix.mcp.model;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record DependencyRecord(
    String ecosystem,
    String name,
    String declaredVersion,
    String resolvedVersion,
    String dependencyType,
    String directOrTransitive,
    String sourceFile,
    String sourceKind,
    String parseStatus) {}
