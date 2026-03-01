# Guardian: Pre-install Security Audit

## Trigger
User invokes `/audit <target>` where target is a GitHub URL, npm package name, or local directory path.

## Workflow

### 1. Resolve target to a local directory

**GitHub URL** (contains github.com):
```bash
TMPDIR=$(mktemp -d)
git clone --depth 1 "<url>" "$TMPDIR/repo" 2>&1
SCAN_DIR="$TMPDIR/repo"
```

**npm package** (no slashes, no dots, or starts with @):
```bash
TMPDIR=$(mktemp -d)
cd "$TMPDIR" && npm pack "<package>" 2>&1 && tar -xzf *.tgz
SCAN_DIR="$TMPDIR/package"
```

**pip package** (prefixed with `pip:` or `pypi:`):
```bash
TMPDIR=$(mktemp -d)
pip download --no-deps --no-binary :all: "<package>" -d "$TMPDIR" 2>&1
cd "$TMPDIR" && tar -xzf *.tar.gz 2>/dev/null || unzip *.whl 2>/dev/null
SCAN_DIR="$TMPDIR"
```

**Local directory** (path exists):
```bash
SCAN_DIR="<path>"
```

### 2. Run the scanner

```bash
bash "$HOME/.claude/skills/guardian/scripts/guardian-scan.sh" "$SCAN_DIR"
```

Capture both stderr (human-readable progress) and stdout (JSON result).

### 3. Parse the JSON result

The scanner outputs JSON to stdout:
```json
{
  "score": 0,
  "verdict": "CLEAN",
  "findings_count": 0,
  "findings": []
}
```

### 4. Present results to the user

Format findings grouped by severity. Use these indicators:

| Verdict | Display |
|---------|---------|
| CLEAN | **CLEAN** — No threats detected. Safe to install. |
| LOW_RISK | **LOW RISK** — Minor concerns, likely fine. Review flagged items. |
| SUSPICIOUS | **SUSPICIOUS** — Multiple warning signs. Review each finding before installing. |
| DANGEROUS | **DANGEROUS** — Strong indicators of malicious code. Do NOT install. |

For each finding, show:
- Severity badge
- File path and line
- Description
- The matched code snippet (truncated)

### 5. Cleanup

```bash
[ -n "${TMPDIR:-}" ] && rm -rf "$TMPDIR"
```

## Important

- Always clone with `--depth 1` to minimize download
- Always clean up temp directories
- Never install or execute the target package — only analyze source
- Timeout clones/downloads after 30 seconds
