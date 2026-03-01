#!/usr/bin/env bash
set -euo pipefail

# Guardian Scanner — detects supply chain attack patterns in source code
# Usage: guardian-scan.sh <directory>
# Output: JSON with score, verdict, and findings

TARGET="${1:-.}"
SCORE=0
declare -a FINDINGS=()

# Colors (only for stderr/terminal)
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "$1" >&2; }

add_finding() {
  local severity="$1" points="$2" file="$3" description="$4" match="${5:-}"
  SCORE=$((SCORE + points))
  # Escape quotes in match for valid JSON
  match="${match//\\/\\\\}"
  match="${match//\"/\\\"}"
  match="${match//$'\n'/\\n}"
  match="${match//$'\r'/}"
  # Truncate long matches
  if [ ${#match} -gt 200 ]; then
    match="${match:0:200}..."
  fi
  FINDINGS+=("{\"severity\":\"${severity}\",\"points\":${points},\"file\":\"${file}\",\"description\":\"${description}\",\"match\":\"${match}\"}")
}

# Verify target exists
if [ ! -d "$TARGET" ]; then
  echo "{\"error\":\"Directory not found: ${TARGET}\"}"
  exit 1
fi

log "${CYAN}Guardian Scanner${NC}"
log "Scanning: ${TARGET}"
log ""

# ─── CRITICAL (+40 points) ─────────────────────────────────────────

log "${RED}[CRITICAL] Checking encoded eval patterns...${NC}"

# Encoded eval: eval + Buffer.from / atob / base64
while IFS= read -r file; do
  while IFS= read -r match; do
    add_finding "CRITICAL" 40 "$file" "Encoded eval — eval combined with base64/Buffer decoding" "$match"
  done < <(grep -nE 'eval\s*\(.*([Bb]uffer\.from|atob|base64|fromCharCode)' "$file" 2>/dev/null || true)
  while IFS= read -r match; do
    add_finding "CRITICAL" 40 "$file" "Encoded eval — base64 decoded then eval'd" "$match"
  done < <(grep -nE '([Bb]uffer\.from|atob)\s*\(.*eval' "$file" 2>/dev/null || true)
done < <(find "$TARGET" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" -o -name "*.cjs" \) \
  ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/dist/*" ! -path "*/build/*" 2>/dev/null)

log "${RED}[CRITICAL] Checking lifecycle hooks with remote execution...${NC}"

# postinstall scripts that fetch/execute remote code
if [ -f "$TARGET/package.json" ]; then
  postinstall=$(grep -E '"(preinstall|postinstall|preuninstall)"' "$TARGET/package.json" 2>/dev/null || true)
  if [ -n "$postinstall" ]; then
    if echo "$postinstall" | grep -qE '(curl|wget|node\s+-e|npx\s|sh\s+-c)'; then
      add_finding "CRITICAL" 40 "package.json" "Lifecycle hook executes remote code or runs shell commands" "$postinstall"
    fi
  fi
fi

log "${RED}[CRITICAL] Checking credential file access...${NC}"

# Accessing credential files
while IFS= read -r file; do
  while IFS= read -r match; do
    add_finding "CRITICAL" 40 "$file" "Reads sensitive credential files" "$match"
  done < <(grep -nE '(\.npmrc|\.yarnrc|\.ssh|\.aws|\.gnupg|\.docker|wallet|keychain|\.env\b|credentials|\.netrc)' "$file" 2>/dev/null | \
    grep -vE '(README|\.md|CHANGELOG|LICENSE|\.example|\.sample|\.template|\.test\.|\.spec\.)' || true)
done < <(find "$TARGET" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.sh" \) \
  ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/dist/*" 2>/dev/null)

log "${RED}[CRITICAL] Checking Python setup.py shell execution...${NC}"

# Python setup.py with subprocess
if [ -f "$TARGET/setup.py" ]; then
  while IFS= read -r match; do
    add_finding "CRITICAL" 40 "setup.py" "setup.py executes shell commands during install" "$match"
  done < <(grep -nE '(subprocess\.(run|call|Popen|check_output)|commands\.getoutput)' "$TARGET/setup.py" 2>/dev/null || true)
fi

# ─── HIGH (+25 points) ────────────────────────────────────────────

log "${YELLOW}[HIGH] Checking shell execution with interpolation...${NC}"

# Shell exec with template literal interpolation
while IFS= read -r file; do
  while IFS= read -r match; do
    add_finding "HIGH" 25 "$file" "Shell execution with template literal interpolation" "$match"
  done < <(grep -nE '(exec|execSync|spawn|spawnSync)\s*\(\s*`' "$file" 2>/dev/null || true)
done < <(find "$TARGET" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" -o -name "*.cjs" \) \
  ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/dist/*" 2>/dev/null)

log "${YELLOW}[HIGH] Checking network calls in install scripts...${NC}"

# Network calls inside install scripts
for script in "$TARGET/scripts/postinstall"* "$TARGET/scripts/preinstall"* "$TARGET/postinstall"*; do
  [ -f "$script" ] || continue
  while IFS= read -r match; do
    add_finding "HIGH" 25 "$script" "Network call inside install script" "$match"
  done < <(grep -nE '(https?://|fetch\(|axios\.|request\(|http\.get|urllib|requests\.(get|post))' "$script" 2>/dev/null || true)
done

log "${YELLOW}[HIGH] Checking for obfuscated strings...${NC}"

# Long hex strings or fromCharCode chains
while IFS= read -r file; do
  while IFS= read -r match; do
    add_finding "HIGH" 25 "$file" "Long hex-encoded string — possible obfuscation" "$match"
  done < <(grep -nE '\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){15,}' "$file" 2>/dev/null || true)
  while IFS= read -r match; do
    add_finding "HIGH" 25 "$file" "fromCharCode chain — possible obfuscation" "$match"
  done < <(grep -nE 'fromCharCode\s*\(\s*[0-9]+\s*(,\s*[0-9]+\s*){7,}\)' "$file" 2>/dev/null || true)
done < <(find "$TARGET" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" -o -name "*.cjs" \) \
  ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/dist/*" 2>/dev/null)

# ─── MEDIUM (+10 points) ──────────────────────────────────────────

log "${CYAN}[MEDIUM] Checking standalone eval...${NC}"

while IFS= read -r file; do
  while IFS= read -r match; do
    add_finding "MEDIUM" 10 "$file" "Standalone eval usage" "$match"
  done < <(grep -nE '\beval\s*\(' "$file" 2>/dev/null | \
    grep -vE '(//.*eval|/\*.*eval|\*.*eval|\.test\.|\.spec\.|jest|mocha)' || true)
done < <(find "$TARGET" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" -o -name "*.cjs" \) \
  ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/dist/*" ! -path "*test*" 2>/dev/null)

log "${CYAN}[MEDIUM] Checking dynamic require/import...${NC}"

while IFS= read -r file; do
  while IFS= read -r match; do
    add_finding "MEDIUM" 10 "$file" "Dynamic require/import with variable argument" "$match"
  done < <(grep -nE '(require|import)\s*\(\s*[^"'"'"'`]' "$file" 2>/dev/null | \
    grep -vE '(webpack|vite|rollup|jest\.mock|\.test\.|\.spec\.)' || true)
done < <(find "$TARGET" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" -o -name "*.cjs" \) \
  ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/dist/*" 2>/dev/null)

log "${CYAN}[MEDIUM] Checking file access outside project...${NC}"

while IFS= read -r file; do
  while IFS= read -r match; do
    add_finding "MEDIUM" 10 "$file" "File access potentially outside project directory" "$match"
  done < <(grep -nE "(readFile|writeFile|readFileSync|writeFileSync|createReadStream|createWriteStream)\s*\(.*(\.\./\.\./|process\.env\.(HOME|USERPROFILE)|homedir|'/etc|'/tmp)" "$file" 2>/dev/null || true)
done < <(find "$TARGET" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" -o -name "*.cjs" \) \
  ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/dist/*" 2>/dev/null)

log "${CYAN}[MEDIUM] Checking permission changes...${NC}"

while IFS= read -r file; do
  while IFS= read -r match; do
    add_finding "MEDIUM" 10 "$file" "Overly permissive file permission change" "$match"
  done < <(grep -nE '(chmod\s+777|chmod\s+0?777|chmodSync.*0o?777|\.chmod\(.*777)' "$file" 2>/dev/null || true)
done < <(find "$TARGET" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.sh" -o -name "*.py" \) \
  ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/dist/*" 2>/dev/null)

# ─── LOW (+5 points) ─────────────────────────────────────────────

log "[LOW] Checking for missing README..."

if [ ! -f "$TARGET/README.md" ] && [ ! -f "$TARGET/readme.md" ] && [ ! -f "$TARGET/README" ]; then
  add_finding "LOW" 5 "-" "No README file found" ""
fi

log "[LOW] Checking for minified source files..."

while IFS= read -r file; do
  linecount=$(wc -l < "$file" | tr -d ' ')
  if [ "$linecount" -le 3 ]; then
    charcount=$(wc -c < "$file" | tr -d ' ')
    if [ "$charcount" -gt 5000 ]; then
      add_finding "LOW" 5 "$file" "Minified JS in source (not dist) — may hide malicious code" "Lines: ${linecount}, Chars: ${charcount}"
    fi
  fi
done < <(find "$TARGET" -type f -name "*.js" \
  ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/dist/*" ! -path "*/build/*" ! -path "*min.js" 2>/dev/null)

# ─── VERDICT ──────────────────────────────────────────────────────

if [ $SCORE -le 10 ]; then
  VERDICT="CLEAN"
elif [ $SCORE -le 30 ]; then
  VERDICT="LOW_RISK"
elif [ $SCORE -le 60 ]; then
  VERDICT="SUSPICIOUS"
else
  VERDICT="DANGEROUS"
fi

# Build JSON findings array
FINDINGS_JSON="["
for i in "${!FINDINGS[@]}"; do
  if [ $i -gt 0 ]; then
    FINDINGS_JSON+=","
  fi
  FINDINGS_JSON+="${FINDINGS[$i]}"
done
FINDINGS_JSON+="]"

log ""
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

case $VERDICT in
  CLEAN)     log "${GREEN}VERDICT: CLEAN (score: ${SCORE})${NC}" ;;
  LOW_RISK)  log "${CYAN}VERDICT: LOW_RISK (score: ${SCORE})${NC}" ;;
  SUSPICIOUS) log "${YELLOW}VERDICT: SUSPICIOUS (score: ${SCORE})${NC}" ;;
  DANGEROUS) log "${RED}VERDICT: DANGEROUS (score: ${SCORE})${NC}" ;;
esac

log "Findings: ${#FINDINGS[@]}"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Output JSON to stdout
cat <<EOF
{"score":${SCORE},"verdict":"${VERDICT}","findings_count":${#FINDINGS[@]},"findings":${FINDINGS_JSON}}
EOF
