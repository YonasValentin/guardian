#!/usr/bin/env bash
set -euo pipefail

# Copies Guardian files into ~/.claude/ and patches settings.json

CLAUDE_DIR="$HOME/.claude"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Installing Guardian into $CLAUDE_DIR ..."

# Copy files
mkdir -p "$CLAUDE_DIR/skills/guardian/scripts"
mkdir -p "$CLAUDE_DIR/hooks"
mkdir -p "$CLAUDE_DIR/commands"

cp "$SCRIPT_DIR/skills/guardian/scripts/guardian-scan.sh" "$CLAUDE_DIR/skills/guardian/scripts/"
cp "$SCRIPT_DIR/skills/guardian/SKILL.md" "$CLAUDE_DIR/skills/guardian/"
cp "$SCRIPT_DIR/hooks/guardian-hook.js" "$CLAUDE_DIR/hooks/"
cp "$SCRIPT_DIR/commands/audit.md" "$CLAUDE_DIR/commands/"

chmod +x "$CLAUDE_DIR/skills/guardian/scripts/guardian-scan.sh"

# Patch settings.json if the hook isn't already registered
SETTINGS="$CLAUDE_DIR/settings.json"

if [ ! -f "$SETTINGS" ]; then
  cat > "$SETTINGS" << 'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": { "tool_name": "Bash" },
        "hooks": [
          {
            "type": "command",
            "command": "node \"$HOME/.claude/hooks/guardian-hook.js\""
          }
        ]
      }
    ]
  }
}
EOF
  echo "Created settings.json with Guardian hook."
elif ! grep -q "guardian-hook" "$SETTINGS"; then
  echo ""
  echo "NOTE: You need to add the Guardian hook to your settings.json manually."
  echo "Add this under \"hooks\":{  ...  }:"
  echo ""
  cat << 'EOF'
    "PreToolUse": [
      {
        "matcher": { "tool_name": "Bash" },
        "hooks": [
          {
            "type": "command",
            "command": "node \"$HOME/.claude/hooks/guardian-hook.js\""
          }
        ]
      }
    ]
EOF
  echo ""
  echo "Or merge it with your existing PreToolUse hooks if you already have some."
else
  echo "Guardian hook already in settings.json, skipping."
fi

echo ""
echo "Done. You can now use /audit <target> in Claude Code."
