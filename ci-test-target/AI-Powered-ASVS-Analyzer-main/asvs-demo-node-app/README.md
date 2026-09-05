# ASVS Demo Secure Node App

This is a small Node.js/Express application created specifically for the **ASVS Compliance & Maturity Analyzer** demo.

It is not intended to represent a complete production application. Its purpose is to contain security constructs that match the analyzer's actual AST and regex detectors.

## Why this project

The analyzer uses Tree-sitter AST queries for structural checks and regex patterns as fallback coverage. The AST engine explicitly distinguishes executable code structures from text inside comments/strings.

This demo therefore uses the exact constructs recognized by the current detector implementation, including:

- bcrypt password hashing
- bcrypt salt/work factor
- rate limiting
- secure random bytes
- TOTP verification
- secure/HttpOnly/SameSite cookies
- session regeneration and destruction
- JWT signing and verification
- JWT audience validation
- JWT algorithm allowlist
- HSTS
- CSP
- X-Frame-Options
- Referrer-Policy
- RBAC/authorization
- parameterized query example
- input validation
- HTML output encoding
- SSRF host allowlist
- safe command execution configuration
- AES-256-GCM encryption
- IV/nonce generation
- sensitive-data encryption
- browser storage cleanup
- file-size checking
- path.basename
- secure upload directory
- filename sanitization
- antivirus scan placeholder
- GraphQL introspection disabled
- GraphQL depth limiting
- directory listing disabled
- TRACE blocking
- structured logging
- exception handling
- unhandled-exception hook
- mutex/lock usage

## Run locally

```bash
npm install
npm test
npm start
```

The server listens on:

`http://localhost:3000`

## Analyzer demo

Upload the whole project folder to the analyzer.

For the cleanest result, upload these source files:

- `server.js`
- `test.js`

Do not upload `README.md` as source code if your analyzer treats all uploaded text as analyzable code.

## Expected presentation flow

1. Upload the project.
2. Run ASVS analysis.
3. Show AST findings and the `AST` method tag.
4. Show regex fallback findings and the `Regex` method tag.
5. Open a finding such as `11.4.2` and show the bcrypt call.
6. Show cookie/security-header findings.
7. Show authentication/session/JWT findings.
8. Show file-handling findings.
9. Show category coverage and weighted maturity score.
10. Export Excel/PDF.
11. Use the same project in the GitHub Actions PR demo.

## Important

The exact final percentage depends on the analyzer's full ASVS mapping/scoring logic and whether duplicate requirement IDs are merged. This project is deliberately optimized for the detector patterns in the supplied `patterns.js` and `astEngine.js`; it does not guarantee a particular final percentage without running the actual analyzer.
