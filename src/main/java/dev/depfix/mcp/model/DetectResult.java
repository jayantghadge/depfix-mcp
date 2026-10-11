package dev.depfix.mcp.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record DetectResult(
    String owner,
    String repo,
    String branch,
    List<DetectedFile> files,
    List<String> warnings,
    String error) {}
