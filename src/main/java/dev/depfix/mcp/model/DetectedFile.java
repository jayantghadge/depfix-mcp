package dev.depfix.mcp.model;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record DetectedFile(
    String path,
    String ecosystem,
    String fileRole,
    boolean supported,
    String reason) {}
