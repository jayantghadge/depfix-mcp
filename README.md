# DepFix MCP — Phase 1

Read-only MCP server that takes a **GitHub repository URL in chat** and returns a
**structured dependency inventory**. Phase 1 stops at inventory — no vulnerability
matching, upgrades, or pull requests.

- Runtime: Java 21, Spring Boot 3.4, Spring AI 1.0 (`spring-ai-starter-mcp-server`, STDIO)
- Build: Gradle wrapper (`./gradlew`), no system Gradle install needed
- Source: GitHub REST API, read-only, bounded retrieval (max 60 files, 1 MB/file)
- Target repos can be **any language** — Java 21 is only DepFix's own runtime

## Tools

| Tool | Purpose |
|---|---|
| `configure_repository` | Validate URL, resolve branch (default via API), check read access |
| `detect_repository_ecosystems` | List manifests/lockfiles + parser support (detection ≠ extraction) |
| `analyze_dependencies` | Structured inventory: declared vs resolved versions, scopes, warnings |

## Supported formats (Core-5 scope)

| Ecosystem | File | What you get |
|---|---|---|
| Maven | `pom.xml` | Direct deps, `${property}` versions, scopes; unmanaged versions reported with `null` + warning |
| npm | `package.json` | Constraints (`^4.2` stays a constraint, never a resolved version) + prod/dev/peer/optional |
| npm | `package-lock.json` | Resolved versions (v1 + v2/v3), dev flag |
| pip | `requirements.txt` | Constraints, extras, markers; includes/options/editables flagged |
| Gradle | `build.gradle(.kts)` | String-literal deps; `ext`/`extra` version refs resolved from the same file; catalogs, BOM-managed and dynamic versions flagged, never executed |
| Go | `go.mod` | Requirements, direct vs `// indirect` |

All other known files (`yarn.lock`, `pnpm-lock.yaml`, `pyproject.toml`, `Cargo.*`,
`composer.*`, `Gemfile*`, `*.csproj`, …) are **detected but reported unsupported** —
never silently skipped.

## Setup

```bash
cd ~/depfix-mcp
./gradlew clean build
```

Wire into OpenCode — add the `mcp.depfix` block to your global
`~/.config/opencode/opencode.jsonc` (or project `opencode.json`), fixing the jar path:

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

Restart OpenCode / re-open the folder. Check `opencode mcp list` shows
`depfix ✓ connected`. STDIO logs go to `./build/depfix-mcp.log`
(stdout stays clean for the MCP protocol).

## Usage (chat)

> Analyze dependencies in `https://github.com/OWNER/REPO`.

OpenCode calls `configure_repository` → `detect_repository_ecosystems` →
`analyze_dependencies`. No `GITHUB_OWNER`/`GITHUB_REPO` env vars needed.

## Scope: public repositories only

DepFix Phase 1 supports **public repositories only**. There is no authentication:
no tokens in config, chat, or environment, and the server sends no
`Authorization` header. Requests for repositories that are private or do not
exist return a plain "not found — public repositories only" message.

## Limitations

- No transitive closure beyond what lockfiles state; no vulnerability data
- Manifest constraints are never inferred into resolved versions
- Build files are parsed as text, never executed (catalogs stay unresolved)
- Anonymous GitHub API calls are rate-limited (60 req/hr); keep scans small or retry after reset

## How it works — user walkthrough

One-time setup is build → `depfix ✓ connected` in `opencode mcp list`.
After that, each repo is one sentence:

> Analyze dependencies in `https://github.com/OWNER/REPO`.

OpenCode calls `configure_repository` → `detect_repository_ecosystems` →
`analyze_dependencies` and reports the inventory (declared vs resolved versions,
scopes, source files) plus warnings for anything it could not parse.

| Situation | What you experience |
|---|---|
| Public repo | Just works — no setup, no questions. |
| Private or missing repo | Plain "not found — public repositories only" message. |
| URL missing | OpenCode asks *"Which GitHub repository should I analyze?"* — reply with the link. |
| Wrong branch | *"Branch 'xyz' not found, default is 'main'."* — confirm or correct. |

Tips:

- Append `on branch develop` to scan a non-default branch; omit it and DepFix
  resolves the repo's real default branch (never assumes `main`).
- Follow up on the result: *"which of these are dev-only?"* or
  *"summarize by ecosystem"* — OpenCode reasons over the structured inventory.
- Append `use depfix` if a prompt is ambiguous about which tool to use.
- After rebuilding the jar (`./gradlew clean build`), just restart OpenCode —
  the config points at the jar path, so no re-registration is needed.
