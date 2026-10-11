package dev.depfix.mcp.github;

/** Normalized reference to a GitHub repository plus the branch/ref to analyze. */
public record RepositoryRef(String owner, String repo, String branch) {}
