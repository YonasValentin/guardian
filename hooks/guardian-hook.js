#!/usr/bin/env node

// Guardian Hook — intercepts install commands and piped remote scripts
// Registered as a PreToolUse hook in settings.json
// Reads hook event from stdin, outputs JSON response to stdout

const fs = require("fs");

async function main() {
  let input = "";
  for await (const chunk of process.stdin) {
    input += chunk;
  }

  let event;
  try {
    event = JSON.parse(input);
  } catch {
    // Not valid JSON, pass through
    process.exit(0);
  }

  const toolName = event.tool_name || "";
  const toolInput = event.tool_input || {};

  // Only intercept Bash tool calls
  if (toolName !== "Bash") {
    process.exit(0);
  }

  const command = toolInput.command || "";

  // ── Pattern 1: Remote script piped to shell ──
  // curl/wget piped to sh/bash/zsh — requires user confirmation
  const pipeToShellPattern =
    /\b(curl|wget)\b.*\|\s*(ba)?sh\b|\b(curl|wget)\b.*\|\s*zsh\b|\b(curl|wget)\b.*\|\s*sudo\s+(ba)?sh/;

  if (pipeToShellPattern.test(command)) {
    // Block with a reason — user gets prompted
    const json = JSON.stringify({
      decision: "block",
      reason:
        "Guardian: This command pipes a remote script straight into a shell. " +
        "You have no idea what that script contains until it's already running. " +
        "Download it first, read it, then run it.",
    });
    process.stdout.write(json);
    process.exit(0);
  }

  // ── Pattern 2: Package install commands ──
  // npm/yarn/pnpm/bun/pip/brew/cargo/go install — inject context
  const installPatterns = [
    /\bnpm\s+(install|i|add|ci)\b/,
    /\byarn\s+(add|install)\b/,
    /\bpnpm\s+(add|install|i)\b/,
    /\bbun\s+(add|install|i)\b/,
    /\bpip3?\s+install\b/,
    /\bbrew\s+install\b/,
    /\bcargo\s+(install|add)\b/,
    /\bgo\s+(install|get)\b/,
    /\bgem\s+install\b/,
    /\bcomposer\s+(require|install)\b/,
  ];

  const isInstall = installPatterns.some((p) => p.test(command));

  if (isInstall) {
    // Extract package names (best effort)
    const packages = extractPackageNames(command);
    const packageList =
      packages.length > 0 ? packages.join(", ") : "unknown packages";

    const json = JSON.stringify({
      decision: "approve",
      additionalContext:
        `Guardian: About to install ${packageList}. ` +
        "If you haven't used these before, run `/audit <package>` first " +
        "to check for anything sketchy.",
    });
    process.stdout.write(json);
    process.exit(0);
  }

  // ── Default: pass through silently ──
  process.exit(0);
}

function extractPackageNames(command) {
  const packages = [];

  // Remove flags (--save-dev, -D, -g, etc.)
  const cleaned = command
    .replace(/\s+--?\w[\w-]*(=\S+)?/g, " ")
    .replace(/\s+-[a-zA-Z]\s/g, " ");

  // npm install <packages>
  let match = cleaned.match(/\bnpm\s+(?:install|i|add)\s+(.+)/);
  if (match) {
    return match[1].trim().split(/\s+/).filter(validPkg);
  }

  // yarn add <packages>
  match = cleaned.match(/\byarn\s+add\s+(.+)/);
  if (match) {
    return match[1].trim().split(/\s+/).filter(validPkg);
  }

  // pnpm add <packages>
  match = cleaned.match(/\bpnpm\s+(?:add|install|i)\s+(.+)/);
  if (match) {
    return match[1].trim().split(/\s+/).filter(validPkg);
  }

  // bun add <packages>
  match = cleaned.match(/\bbun\s+(?:add|install|i)\s+(.+)/);
  if (match) {
    return match[1].trim().split(/\s+/).filter(validPkg);
  }

  // pip install <packages>
  match = cleaned.match(/\bpip3?\s+install\s+(.+)/);
  if (match) {
    return match[1].trim().split(/\s+/).filter(validPkg);
  }

  // brew install <packages>
  match = cleaned.match(/\bbrew\s+install\s+(.+)/);
  if (match) {
    return match[1].trim().split(/\s+/).filter(validPkg);
  }

  return packages;
}

function validPkg(name) {
  // Filter out things that look like flags or empty strings
  return name && !name.startsWith("-") && name.length > 0;
}

main().catch(() => process.exit(0));
