# Guardian

A security scanner for Claude Code that checks packages and repos for supply chain attack patterns before you install them.

## Why this exists

People blindly install packages all the time. So does Claude. Last year:

- **NX** (4.6M weekly downloads) had credentials stolen through a compromised package
- **Shai-Hulud** worm spread across 500+ npm packages
- **Rspack** (445K users) shipped crypto miners through a supply chain attack

Guardian catches the patterns these attacks use: encoded code execution, postinstall scripts that phone home, credential file reads, obfuscated strings. It's a ~200 line bash script, not a SaaS product. You can read the whole thing in a few minutes.

## What you get

**`/audit <target>`** — a slash command that scans a GitHub repo, npm package, pip package, or local directory and tells you if it looks safe. Returns one of four verdicts:

| Score | Verdict | Meaning |
|-------|---------|---------|
| 0-10 | CLEAN | Nothing found. Go ahead. |
| 11-30 | LOW_RISK | Minor stuff. Probably fine, but check the findings. |
| 31-60 | SUSPICIOUS | Several red flags. Read the findings before installing. |
| 61+ | DANGEROUS | Very likely malicious. Don't install this. |

**PreToolUse hook** — runs automatically when Claude tries to execute install commands or pipe remote scripts to a shell:

- `curl ... | bash` type commands get blocked with a warning
- `npm install`, `pip install`, etc. get a quiet nudge reminding you that `/audit` exists
- Everything else passes through silently

## What it scans for

**Critical** (+40 points each)
- Encoded code execution — the classic "decode-and-run" pattern (base64 + execution)
- `postinstall` scripts that curl/wget or run arbitrary code on install
- Code that reads `.npmrc`, `.ssh`, `.aws`, `credentials`, or keychain files
- Python `setup.py` files that call subprocess during install

**High** (+25 points)
- Shell commands built with template literals — injection waiting to happen
- Network calls inside install scripts
- Long hex strings or `fromCharCode` chains — obfuscation

**Medium** (+10 points)
- Dynamic `require()` / `import()` with variable arguments
- File reads targeting paths outside the project directory
- `chmod 777`

**Low** (+5 points)
- No README (sketchy for a published package)
- Minified JS in source directories (not in dist/)

## Install

```bash
git clone https://github.com/yonasvalentin/guardian.git
cd guardian
bash install.sh
```

The install script copies files into `~/.claude/` and tells you how to register the hook in your `settings.json`.

If you already have a `settings.json` with other hooks, you'll need to merge the PreToolUse entry manually. The script shows you exactly what to add.

## Manual install

If you prefer to do it yourself:

```
~/.claude/
  skills/guardian/
    SKILL.md
    scripts/guardian-scan.sh
  hooks/
    guardian-hook.js
  commands/
    audit.md
```

Then add this to your `~/.claude/settings.json` under `"hooks"`:

```json
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
```

## Usage

```
/audit lodash
/audit https://github.com/someone/some-package
/audit pip:requests
/audit ./local-directory
```

The scanner runs entirely locally. Nothing gets sent anywhere. It greps source files for known-bad patterns and adds up a score.

## Running the scanner directly

You can also run the bash script on its own without Claude:

```bash
bash ~/.claude/skills/guardian/scripts/guardian-scan.sh /path/to/code
```

Progress output goes to stderr (with colors). JSON result goes to stdout.

## Limitations

This is pattern matching, not static analysis. It will miss:

- Novel obfuscation techniques it hasn't seen before
- Malicious code that doesn't match any of the current patterns
- Anything hidden in binary files or images

It will also false-positive on legitimate code that reads `.env` files or uses dynamic execution for valid reasons. The scoring is weighted so a single low-severity match won't tank a package.

If something scores SUSPICIOUS or higher, read the actual findings before deciding. The scanner tells you exactly which file and line triggered each match.

## License

MIT
