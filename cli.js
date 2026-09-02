#!/usr/bin/env node
// cli.js — Standalone CI/CD entry point for the ASVS Compliance & Maturity Analyzer.
//
// Runs the exact same AST engine (src/astEngine.js) used by the browser app, plus a
// regex fallback, against a directory of source files — no browser, no Vite, just Node.
// Designed to be called from a GitHub Action on every pull request.
//
// Usage:
//   node cli.js [--path <dir>] [--min-level <level>] [--project <name>]
//
// Exit codes:
//   0 = maturity level meets or exceeds --min-level (default: "Level 1")
//   1 = maturity level below threshold, OR a fatal error occurred
//
// This intentionally duplicates a slim copy of the regex PATTERNS from src/App.jsx rather
// than importing App.jsx directly, since App.jsx is a React component file with browser-only
// concerns (hooks, JSX) that don't belong in a CLI context. If PATTERNS changes in App.jsx,
// mirror the change here — see PATTERNS_SYNC_NOTE below.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { initAstEngine, runAstOnFiles } from "./src/astEngine.js";
import { PATTERNS } from "./src/patterns.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── CLI args ──────────────────────────────────────────────────────
function parseArgs(argv) {
  const args = { path: ".", minLevel: "Level 1", project: "CI Scan" };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--path") args.path = argv[++i];
    else if (argv[i] === "--min-level") args.minLevel = argv[++i];
    else if (argv[i] === "--project") args.project = argv[++i];
  }
  return args;
}

// ── File discovery ────────────────────────────────────────────────
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".venv", "__pycache__"]);
const SUPPORTED_EXT = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py"]);

function walkDir(dir, results = []) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name.startsWith(".") || SKIP_DIRS.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkDir(fullPath, results);
    } else if (SUPPORTED_EXT.has(path.extname(entry.name))) {
      results.push(fullPath);
    }
  }
  return results;
}

// ── Regex PATTERNS (slim copy — PATTERNS_SYNC_NOTE: keep in sync with src/App.jsx) ──
function analyzeCodeRegex(combined) {
  const findings = [];
  const matched = new Set();
  for (const catPatterns of Object.values(PATTERNS)) {
    for (const p of catPatterns) {
      if (!matched.has(p.id) && p.regex.test(combined)) {
        matched.add(p.id);
        findings.push({ reqId: p.id, confidence: p.confidence, note: p.note, method: "regex" });
      }
    }
  }
  return findings;
}

// ── Severity-weighted scoring (mirrors server.py's compute_weighted_score) ──
const LEVEL_WEIGHTS = { "1": 3, "2": 2, "3": 1 };

function computeWeightedScore(reqs) {
  if (!reqs.length) return { pct: 0, level: "Not Assessed" };
  let totalWeight = 0, earnedWeight = 0;
  let l1Total = 0, l1Done = 0, l12Total = 0, l12Done = 0;
  for (const r of reqs) {
    const lvl = String(r.level || "1");
    const w = LEVEL_WEIGHTS[lvl] || 1;
    const done = !!r.implemented;
    totalWeight += w;
    if (done) earnedWeight += w;
    if (lvl === "1") { l1Total++; if (done) l1Done++; }
    if (lvl === "1" || lvl === "2") { l12Total++; if (done) l12Done++; }
  }
  const pct = totalWeight ? Math.round((earnedWeight / totalWeight) * 100) : 0;
  const l1Pct = l1Total ? (l1Done / l1Total) * 100 : 100;
  const l12Pct = l12Total ? (l12Done / l12Total) * 100 : 100;
  let level;
  if (l1Pct >= 90 && l12Pct >= 70) level = "Level 2";
  else if (l1Pct >= 70) level = "Level 1";
  else level = "Below Level 1";
  return { pct, level };
}

const LEVEL_RANK = { "Below Level 1": 0, "Level 1": 1, "Level 2": 2 };

// ── Main ──────────────────────────────────────────────────────────
async function main() {
  const args = parseArgs(process.argv.slice(2));
  const scanDir = path.resolve(args.path);

  if (!fs.existsSync(scanDir)) {
    console.error(`Error: path does not exist: ${scanDir}`);
    process.exit(1);
  }

  console.log(`\nASVS Compliance & Maturity Analyzer — CI Scan`);
  console.log(`Project: ${args.project}`);
  console.log(`Scanning: ${scanDir}\n`);

  const requirementsPath = path.join(__dirname, "asvs_5.0.0_requirements.json");
  if (!fs.existsSync(requirementsPath)) {
    console.error(`Error: asvs_5.0.0_requirements.json not found next to cli.js.`);
    process.exit(1);
  }
  const requirementsData = JSON.parse(fs.readFileSync(requirementsPath, "utf8"));
  const sastReqs = requirementsData.requirements.filter(r => r.verification_method === "SAST");

  // Reuse the same WASM grammar files already shipped for the browser build (public/tree-sitter/)
  // rather than duplicating them — CLI and browser share one copy.
  const wasmDir = path.join(__dirname, "public", "tree-sitter") + path.sep;
  if (!fs.existsSync(wasmDir)) {
    console.error(`Error: WASM grammar files not found at ${wasmDir}`);
    console.error(`Make sure public/tree-sitter/*.wasm exists (see project setup).`);
    process.exit(1);
  }

  const filePaths = walkDir(scanDir);
  if (filePaths.length === 0) {
    console.log("No supported source files found (js/jsx/ts/tsx/py). Nothing to scan.");
    process.exit(0);
  }
  console.log(`Found ${filePaths.length} source file(s) to analyze.\n`);

  const files = filePaths.map(fp => ({
    name: path.basename(fp),
    content: fs.readFileSync(fp, "utf8"),
  }));

  await initAstEngine(wasmDir);
  const { findings: astFindings } = await runAstOnFiles(files);

  const combined = files.map(f => f.content).join("\n");
  const regexFindings = analyzeCodeRegex(combined);

  const astIds = new Set(astFindings.map(f => f.reqId));
  const allFindings = [...astFindings, ...regexFindings.filter(f => !astIds.has(f.reqId))];
  const foundIds = new Set(allFindings.map(f => f.reqId));

  const reqResults = sastReqs.map(r => ({ ...r, implemented: foundIds.has(r.id) }));
  const { pct, level } = computeWeightedScore(reqResults);

  const implementedCount = reqResults.filter(r => r.implemented).length;

  console.log("─".repeat(60));
  console.log(`Controls detected:  ${implementedCount} / ${sastReqs.length}`);
  console.log(`Weighted coverage:  ${pct}%`);
  console.log(`Maturity level:     ${level}`);
  console.log(`AST-detected:       ${astFindings.length} finding(s)`);
  console.log(`Regex-detected:     ${allFindings.length - astFindings.length} finding(s)`);
  console.log("─".repeat(60));

  const gapCount = reqResults.filter(r => !r.implemented).length;
  console.log(`\n${gapCount} SAST-verifiable requirement(s) not detected in this scan.`);

  const minRank = LEVEL_RANK[args.minLevel] ?? LEVEL_RANK["Level 1"];
  const actualRank = LEVEL_RANK[level] ?? 0;

  if (actualRank < minRank) {
    console.log(`\n❌ FAIL: maturity level "${level}" is below the required threshold "${args.minLevel}".`);
    process.exit(1);
  } else {
    console.log(`\n✅ PASS: maturity level "${level}" meets the required threshold "${args.minLevel}".`);
    process.exit(0);
  }
}

main().catch(err => {
  console.error("Fatal error during scan:", err);
  process.exit(1);
});
