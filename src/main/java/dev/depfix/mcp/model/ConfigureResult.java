package dev.depfix.mcp.model;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ConfigureResult(
    String owner,
    String repo,
    String branch,
    boolean branchExplicit,
    boolean readAccess,
    boolean isPrivate,
    String message,
    String error) {}
