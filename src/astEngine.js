// astEngine.js — Tree-sitter based AST analysis for the ASVS Compliance & Maturity Analyzer.
// Runs entirely in-browser via WebAssembly (web-tree-sitter) — no code ever leaves the client,
// consistent with this project's existing privacy design.
//
// WHY AST INSTEAD OF REGEX:
// Regex matches TEXT. It cannot tell the difference between a real function call, the same
// text in a comment, or the same text inside a string literal. AST parsing understands CODE
// STRUCTURE, so it only matches real, executable calls, real object properties, real
// assignments — not text that merely looks similar. Every query below has been verified
// against real test code including comment/string decoys — see project test notes.
//
// VERSION NOTE: web-tree-sitter must be pinned to 0.25.9 to match the WASM ABI baked into
// the tree-sitter-wasms grammar package (0.1.13). Newer web-tree-sitter (0.26+) fails to
// load these grammar files with a "getDylinkMetadata" error — confirmed via direct testing.
//
// Also note: the internal WASM loader requests a file literally named "tree-sitter.wasm"
// (not "web-tree-sitter.wasm") — the file in public/tree-sitter/ must be named exactly that,
// or Vite's dev server will silently 404-fallback to index.html and parsing will fail with
// a cryptic "wasm validation error: failed to match magic number".
//
// COVERAGE: 21 of 247 SAST-verifiable ASVS 5.0.0 requirements as of this version
// (some requirements have both a JavaScript and a Python detector sharing the same ID).
// Everything else still runs through the existing regex PATTERNS as a fallback — see
// how App.jsx merges astFindings + regexFindings, with AST taking priority when both exist.

import { Parser, Language, Query } from "web-tree-sitter";

let parserReady = false;
let jsLang = null;
let pyLang = null;

export async function initAstEngine(wasmBaseUrl = "/tree-sitter/") {
  if (parserReady) return;
  await Parser.init({
    locateFile: (path) => `${wasmBaseUrl}${path}`,
  });
  jsLang = await Language.load(`${wasmBaseUrl}tree-sitter-javascript.wasm`);
  pyLang = await Language.load(`${wasmBaseUrl}tree-sitter-python.wasm`);
  parserReady = true;
}

export function isAstEngineReady() {
  return parserReady;
}

function detectLanguage(filename) {
  if (/\.(py)$/i.test(filename)) return "python";
  if (/\.(js|jsx|ts|tsx|mjs|cjs)$/i.test(filename)) return "javascript";
  return null;
}

function lineOf(node, code) {
  const before = code.slice(0, node.startIndex);
  const lineNumber = before.split("\n").length;
  const lineContent = code.split("\n")[lineNumber - 1]?.trim().slice(0, 100) || "";
  return { lineNumber, lineContent };
}

// ── JavaScript queries ──────────────────────────────────────────────
// `wrap` names the capture representing "the whole match" for line/text reporting.
// Captures are NOT returned in declaration order — always look up by name, never by index.
// NOTE: tree-sitter's #match? predicate does not support the (?i) inline regex flag;
// case-insensitivity uses explicit [Xx] character classes or is skipped where names are
// conventionally lowercase/camelCase in real code (verified against test cases).
const JS_QUERIES = [
  {
    reqId: "11.4.2", confidence: "high", wrap: "call",
    note: "Password hashing function call detected (AST-verified, not just text match)",
    query: `
      (call_expression
        function: (member_expression
          object: (identifier) @obj
          property: (property_identifier) @method
        )
        (#match? @obj "^(bcrypt|argon2)$")
        (#match? @method "^(hash|hashSync|genSalt)")
      ) @call
    `,
  },
  {
    reqId: "1.3.2", confidence: "low", wrap: "call",
    note: "Dynamic code execution via eval() — AST-confirmed real function call",
    query: `(call_expression function: (identifier) @fn (#eq? @fn "eval")) @call`,
  },
  {
    reqId: "13.3.2", confidence: "medium", wrap: "assignment",
    note: "Possible hardcoded secret — string literal assigned to a secret-like variable name",
    query: `
      (variable_declarator
        name: (identifier) @varname
        value: (string) @strval
        (#match? @varname "[Ss][Ee][Cc][Rr][Ee][Tt]|[Aa][Pp][Ii][_]?[Kk][Ee][Yy]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Tt][Oo][Kk][Ee][Nn]")
      ) @assignment
    `,
  },
  {
    reqId: "3.3.4", confidence: "high", wrap: "prop",
    note: "HttpOnly cookie attribute set to a real boolean true (AST-verified object property)",
    query: `(pair key: (property_identifier) @key value: (true) (#eq? @key "httpOnly")) @prop`,
  },
  {
    reqId: "1.2.4", confidence: "low", wrap: "concat", isWrong: true,
    note: "Possible SQL built via string concatenation — AST-detected binary '+' expression containing SQL keywords",
    query: `
      (binary_expression
        left: (string) @sqlstr
        operator: "+"
        (#match? @sqlstr "[Ss][Ee][Ll][Ee][Cc][Tt] |[Ii][Nn][Ss][Ee][Rr][Tt] |[Uu][Pp][Dd][Aa][Tt][Ee] |[Dd][Ee][Ll][Ee][Tt][Ee] ")
      ) @concat
    `,
  },
  {
    reqId: "16.5.3", confidence: "high", wrap: "try",
    note: "Exception handling block detected (AST-verified try/catch, not text matching 'try{' in a string)",
    query: `(try_statement) @try`,
  },
  {
    reqId: "6.5.3", confidence: "high", wrap: "call",
    note: "Secure random token generation via crypto.randomBytes (AST-verified real call)",
    query: `
      (call_expression
        function: (member_expression object: (identifier) @obj property: (property_identifier) @method)
        (#eq? @obj "crypto") (#eq? @method "randomBytes")
      ) @call
    `,
  },
  {
    reqId: "6.3.1", confidence: "medium", wrap: "call",
    note: "Rate limiting / brute force protection detected (AST-verified real call)",
    query: `
      (call_expression function: (identifier) @fn (#match? @fn "^[Rr]ate[Ll]imit")) @call
      (call_expression
        function: (member_expression object: (identifier) @obj property: (property_identifier) @method)
        (#match? @obj "[Ll]imiter") (#eq? @method "limit")
      ) @call
    `,
  },
  {
    reqId: "7.2.4", confidence: "high", wrap: "call",
    note: "Session regeneration on login detected (AST-verified real call)",
    query: `(call_expression function: (member_expression property: (property_identifier) @method) (#eq? @method "regenerate")) @call`,
  },
  {
    reqId: "7.4.1", confidence: "medium", wrap: "call",
    note: "Session invalidation/termination detected (AST-verified real call)",
    query: `(call_expression function: (member_expression property: (property_identifier) @method) (#match? @method "^(destroy|invalidate)$")) @call`,
  },
  {
    reqId: "9.1.1", confidence: "medium", wrap: "call",
    note: "Self-contained token signing detected (AST-verified jwt.sign call)",
    query: `
      (call_expression
        function: (member_expression object: (identifier) @obj property: (property_identifier) @method)
        (#eq? @obj "jwt") (#eq? @method "sign")
      ) @call
    `,
  },
  {
    reqId: "3.3.1", confidence: "high", wrap: "prop",
    note: "Secure cookie attribute set to a real boolean true (AST-verified)",
    query: `(pair key: (property_identifier) @key value: (true) (#eq? @key "secure")) @prop`,
  },
  {
    reqId: "3.3.2", confidence: "high", wrap: "prop",
    note: "SameSite cookie attribute set to Strict/Lax (AST-verified real string value)",
    query: `(pair key: (property_identifier) @key value: (string) @val (#eq? @key "sameSite") (#match? @val "[Ss]trict|[Ll]ax")) @prop`,
  },
  {
    reqId: "3.4.1", confidence: "high", wrap: "call",
    note: "HSTS header set via real setHeader/set call (AST-verified)",
    query: `
      (call_expression
        function: (member_expression property: (property_identifier) @method)
        arguments: (arguments (string) @arg1 . (_)?)
        (#match? @method "^(setHeader|set)$")
        (#match? @arg1 "Strict-Transport-Security")
      ) @call
    `,
  },
  {
    reqId: "3.4.3", confidence: "high", wrap: "call",
    note: "Content-Security-Policy header set via real setHeader/set call (AST-verified)",
    query: `
      (call_expression
        function: (member_expression property: (property_identifier) @method)
        arguments: (arguments (string) @arg1 . (_)?)
        (#match? @method "^(setHeader|set)$")
        (#match? @arg1 "Content-Security-Policy")
      ) @call
    `,
  },
  {
    reqId: "3.4.6", confidence: "high", wrap: "call",
    note: "X-Frame-Options header set via real setHeader/set call (AST-verified)",
    query: `
      (call_expression
        function: (member_expression property: (property_identifier) @method)
        arguments: (arguments (string) @arg1 . (_)?)
        (#match? @method "^(setHeader|set)$")
        (#match? @arg1 "X-Frame-Options")
      ) @call
    `,
  },
  {
    reqId: "8.2.1", confidence: "medium", wrap: "call",
    note: "Authorization/RBAC check detected (AST-verified real function call)",
    query: `(call_expression function: (identifier) @fn (#match? @fn "^(authorize|hasRole|checkPermission|requireRole)$")) @call`,
  },
  {
    reqId: "11.3.1", confidence: "low", wrap: "call", isWrong: true,
    note: "Weak cryptographic hash algorithm (MD5/SHA1) detected via real createHash call",
    query: `
      (call_expression
        function: (member_expression object: (identifier) @obj property: (property_identifier) @method)
        arguments: (arguments (string) @alg)
        (#eq? @obj "crypto") (#eq? @method "createHash")
        (#match? @alg "md5|sha1")
      ) @call
    `,
  },
  {
    reqId: "5.3.2", confidence: "medium", wrap: "call",
    note: "Path traversal protection via path.basename (AST-verified real call)",
    query: `
      (call_expression
        function: (member_expression object: (identifier) @obj property: (property_identifier) @method)
        (#eq? @obj "path") (#eq? @method "basename")
      ) @call
    `,
  },
];

// ── Python queries ──────────────────────────────────────────────────
const PY_QUERIES = [
  {
    reqId: "11.4.2", confidence: "high", wrap: "call",
    note: "Password hashing function call detected (AST-verified)",
    query: `
      (call
        function: (attribute object: (identifier) @obj attribute: (identifier) @method)
        (#match? @obj "^(bcrypt|argon2)$") (#match? @method "^(hashpw|hash)")
      ) @call
    `,
  },
  {
    reqId: "1.3.2", confidence: "low", wrap: "call",
    note: "Dynamic code execution via eval() — AST-confirmed real function call",
    query: `(call function: (identifier) @fn (#eq? @fn "eval")) @call`,
  },
  {
    reqId: "13.3.2", confidence: "medium", wrap: "assignment",
    note: "Possible hardcoded secret — string literal assigned to a secret-like variable name",
    query: `
      (assignment
        left: (identifier) @varname
        right: (string) @strval
        (#match? @varname "[Ss][Ee][Cc][Rr][Ee][Tt]|[Aa][Pp][Ii][_]?[Kk][Ee][Yy]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Tt][Oo][Kk][Ee][Nn]")
      ) @assignment
    `,
  },
  {
    reqId: "16.5.3", confidence: "high", wrap: "try",
    note: "Exception handling block detected (AST-verified try/except)",
    query: `(try_statement) @try`,
  },
  {
    reqId: "6.5.3", confidence: "high", wrap: "call",
    note: "Secure random token generation via secrets module (AST-verified real call)",
    query: `
      (call
        function: (attribute object: (identifier) @obj attribute: (identifier) @method)
        (#eq? @obj "secrets") (#match? @method "^token_")
      ) @call
    `,
  },
  {
    reqId: "9.1.1", confidence: "medium", wrap: "call",
    note: "Self-contained token signing detected (AST-verified jwt.encode call)",
    query: `
      (call
        function: (attribute object: (identifier) @obj attribute: (identifier) @method)
        (#eq? @obj "jwt") (#eq? @method "encode")
      ) @call
    `,
  },
  {
    reqId: "13.4.2", confidence: "medium", wrap: "assignment",
    note: "Debug mode disabled (AST-verified DEBUG = False assignment)",
    query: `
      (assignment left: (subscript subscript: (string) @key) right: (false) (#match? @key "DEBUG")) @assignment
      (assignment left: (identifier) @varname right: (false) (#match? @varname "DEBUG")) @assignment
    `,
  },
  {
    reqId: "1.2.5", confidence: "high", wrap: "call",
    note: "Command injection protection via subprocess with shell=False (AST-verified)",
    query: `
      (call
        function: (attribute object: (identifier) @obj attribute: (identifier) @method)
        arguments: (argument_list (keyword_argument name: (identifier) @kwname value: (false)))
        (#eq? @obj "subprocess") (#match? @method "^(run|Popen|call)$") (#eq? @kwname "shell")
      ) @call
    `,
  },
];

async function analyzeWithQueries(code, lang, queries) {
  const parser = new Parser();
  parser.setLanguage(lang);
  const tree = parser.parse(code);
  const findings = [];
  const matchedIds = new Set();

  for (const q of queries) {
    if (matchedIds.has(q.reqId)) continue; // one finding per requirement, like the regex engine
    try {
      const query = new Query(lang, q.query);
      const matches = query.matches(tree.rootNode);
      if (matches.length > 0) {
        matchedIds.add(q.reqId);
        const wrapCapture = matches[0].captures.find(c => c.name === q.wrap);
        const node = wrapCapture ? wrapCapture.node : matches[0].captures[0].node;
        const { lineNumber, lineContent } = lineOf(node, code);
        findings.push({
          reqId: q.reqId,
          confidence: q.confidence,
          note: q.note,
          lineNumber,
          lineContent,
          isWrong: !!q.isWrong,
          method: "AST",
        });
      }
    } catch (err) {
      console.error(`AST query failed for ${q.reqId}:`, err);
    }
  }
  return findings;
}

export async function runAstOnFile(filename, code) {
  if (!parserReady) throw new Error("AST engine not initialized — call initAstEngine() first");
  const language = detectLanguage(filename);
  if (!language) return { findings: null, language: null };

  if (language === "javascript") {
    const findings = await analyzeWithQueries(code, jsLang, JS_QUERIES);
    return { findings, language };
  }
  if (language === "python") {
    const findings = await analyzeWithQueries(code, pyLang, PY_QUERIES);
    return { findings, language };
  }
  return { findings: null, language: null };
}

export async function runAstOnFiles(files) {
  const allFindings = [];
  const seenIds = new Set();
  let anyAstSupported = false;

  for (const f of files) {
    const { findings, language } = await runAstOnFile(f.name, f.content);
    if (language) anyAstSupported = true;
    if (findings) {
      for (const finding of findings) {
        if (!seenIds.has(finding.reqId)) {
          seenIds.add(finding.reqId);
          allFindings.push({ ...finding, sourceFile: f.name });
        }
      }
    }
  }
  return { findings: allFindings, anyAstSupported };
}
