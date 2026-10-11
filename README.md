# DepFix MCP

A read-only MCP server for OpenCode. Give it a public GitHub repo URL in chat
and it returns a dependency inventory (Phase 1) and a vulnerability report
(Phase 2). It never edits code, upgrades packages, or opens pull requests.

- Stack: Java 21, Spring Boot 3.4, Spring AI 1.0, Gradle wrapper, STDIO transport
- Data sources (all read-only): GitHub REST API, OSV.dev, CISA KEV, NVD
- Works on repos in any language. Public repositories only - no tokens, no login.

## Setup

```bash
cd ~/depfix-mcp
./gradlew clean build
```

Add this to `~/.config/opencode/opencode.jsonc` (fix the jar path to yours):

```json
{
  "mcp": {
    "depfix": {
      "type": "local",
      "command": ["java", "-jar", "/Users/jayantghadge/depfix-mcp/build/libs/depfix-mcp-0.1.0.jar"],
      "enabled": true,
      "timeout": 30000
    }
  }
}
```

Restart OpenCode, then check `opencode mcp list` shows `depfix connected`.
Logs go to `./build/depfix-mcp.log`. After any rebuild, just restart OpenCode.

## Use it

Inventory:

> Analyze dependencies in `https://github.com/OWNER/REPO`.

Vulnerabilities:

> Check my repo for known vulnerabilities: `https://github.com/OWNER/REPO`.

Add `on branch develop` to scan a non-default branch. If you forget the URL,
OpenCode asks for it. If a prompt is ambiguous, append `use depfix`.

| Situation | What happens |
|---|---|
| Public repo | Just works, no setup, no questions. |
| Private or missing repo | Plain "not found - public repositories only" message. |
| Wrong branch | Tells you the default branch so you can correct it. |

## Tools

| Tool | What it does |
|---|---|
| `configure_repository` | Validates the URL, resolves the branch, checks read access. |
| `detect_repository_ecosystems` | Lists dependency files found and which ones can be parsed. |
| `analyze_dependencies` | Returns the inventory: versions, scopes, source files, warnings. |
| `assess_vulnerabilities` | Returns findings ranked by confidence and urgency, plus a fix plan. |

## Supported files

| Ecosystem | File | Notes |
|---|---|---|
| Maven | `pom.xml` | Direct deps, `${property}` versions, scopes. |
| npm | `package.json` | Constraints stay constraints, never treated as resolved versions. |
| npm | `package-lock.json` | Resolved versions, dev flag. |
| pip | `requirements.txt` | Constraints, extras, markers. |
| Gradle | `build.gradle(.kts)` | `ext`/`extra` refs resolved as text, never executed. |
| Go | `go.mod` | Direct vs `// indirect`. |

Other known files (`yarn.lock`, `pyproject.toml`, `Cargo.*`, `composer.*`,
`Gemfile*`, `*.csproj`, ...) are reported as detected-but-unsupported, never
silently skipped. Version ranges without a pinned or resolved value are skipped
the same way - DepFix guesses nothing.

## How the vulnerability report works

1. One matchable version per package: lockfile first, then `go.mod` minimums,
   then exact pins like `==1.2.3`.
2. OSV.dev matching with local range confirmation. Identity mismatches are
   dropped with a warning. GIT-only ranges stay as `likely`, never dropped.
3. Every CVE checked against the CISA KEV catalog (cached 24h).
4. NVD fills severity gaps only (cached 24h, throttled, optional `NVD_API_KEY`
   for higher limits).
5. Each finding gets confidence (`confirmed`/`likely`), urgency (`urgent` for
   KEV-listed or Critical, `elevated` for High or unknown, else `routine`),
   severity with source, affected ranges, fixed version, and osv.dev links.
6. Findings group into `remediations`: one fix per package with priority,
   target version, upgrade type/risk (`patch`/`minor`/`major`), and which file
   to edit. This is the handoff Phase 3 will act on.

` sources` in the report shows each source as `ok`, `partial`, `stale-cache`,
or `unavailable`. If OSV fails, the report errors instead of pretending to be
clean. If KEV or NVD degrades, the report says so. A clean report means "no
known vulns in these sources", not proof of safety.

## Limits

- No transitive closure beyond what lockfiles state.
- Anonymous GitHub API: 60 requests/hour. Retrying later fixes it.
- Build files are parsed as text, never run.
- Private repos are out of scope.
