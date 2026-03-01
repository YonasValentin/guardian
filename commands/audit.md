Guardian: Scan $ARGUMENTS for supply chain attack patterns.

Follow the workflow in ~/.claude/skills/guardian/SKILL.md to:

1. Resolve the target ($ARGUMENTS) — it can be a GitHub URL, npm package name, pip:package, or local directory path
2. Clone/download to a temp directory if needed (--depth 1, 30s timeout)
3. Run the scanner: bash "$HOME/.claude/skills/guardian/scripts/guardian-scan.sh" <dir>
4. Parse the JSON output from stdout
5. Present findings grouped by severity with the verdict
6. Clean up temp directories

If no argument is provided, scan the current working directory.
