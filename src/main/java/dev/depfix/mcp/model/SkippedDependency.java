package dev.depfix.mcp.model;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record SkippedDependency(
    String ecosystem,
    String name,
    String sourceFile,
    String reason) {}
