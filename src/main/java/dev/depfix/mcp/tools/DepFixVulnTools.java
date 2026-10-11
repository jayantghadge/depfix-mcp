package dev.depfix.mcp.tools;

import dev.depfix.mcp.github.RepositoryRef;
import dev.depfix.mcp.model.VulnReport;
import dev.depfix.mcp.service.VulnerabilityService;
import dev.depfix.mcp.session.RepositoryResolver;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Component;

/**
 * Phase-2 MCP tools. Read-only: assesses pinned dependencies against OSV.dev
 * affected ranges, CISA KEV exploitation status, and NVD severity/advisories.
 * Never suggests or applies upgrades.
 */
@Component
public class DepFixVulnTools {

  private final VulnerabilityService vulns;
  private final RepositoryResolver resolver;

  public DepFixVulnTools(VulnerabilityService vulns, RepositoryResolver resolver) {
    this.vulns = vulns;
    this.resolver = resolver;
  }

  @Tool(name = "assess_vulnerabilities",
      description = "Assess a public GitHub repository for high-priority vulnerabilities: builds the "
          + "Phase-1 inventory, matches pinned versions against OSV.dev ranges, checks CISA KEV "
          + "for known exploitation, enriches severity via NVD, and returns findings classified by "
          + "confidence (confirmed/likely) and urgency (urgent/elevated/routine). Read-only.")
  public VulnReport assessVulnerabilities(
      @ToolParam(description = "GitHub repository URL (optional if configure_repository was already called)", required = false)
      String repository_url,
      @ToolParam(description = "Optional branch or ref", required = false)
      String branch) {
    RepositoryRef ref;
    try {
      ref = resolver.resolve(repository_url, branch);
    } catch (IllegalArgumentException e) {
      return new VulnReport(null, null, null, Instant.now().toString(),
          0, Map.of(), Map.of(), 0, 0, Map.of(), Map.of(), Map.of("osv", "not-queried"),
          List.of(), List.of(), List.of(), List.of(), List.of(), e.getMessage());
    }
    return vulns.assess(ref.owner(), ref.repo(), ref.branch());
  }
}
