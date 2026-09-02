// patterns.js — Single source of truth for regex-based SAST detection patterns.
// Imported by both src/App.jsx (browser) and cli.js (Node/CI) so the two never drift apart.
// IDs are ASVS 5.0.0 requirement IDs — see asvs_5.0.0_requirements.json for full text/category.

export const PATTERNS = {
  "Authentication": [
    { id:"11.4.2", regex:/bcrypt|argon2|scrypt|pbkdf2|password_hash|hashpw/i, confidence:"high", note:"Password hashing function detected" },
    { id:"11.4.4", regex:/bcrypt.*rounds|saltRounds\s*=\s*\d+|work.?factor|pbkdf2.*100000|iterations.*100000/i, confidence:"high", note:"Key stretching / work factor configured" },
    { id:"6.3.1", regex:/rate.?limit|ratelimit|slowDown|brute.?force|max.?attempt|lockout|throttl/i, confidence:"medium", note:"Rate limiting / brute force protection detected" },
    { id:"13.3.2", regex:/api.?key\s*=\s*["'][^"'\s]{8,}|secret\s*=\s*["'][^"'\s]{8,}/i, confidence:"low", note:"Possible hardcoded secret — review needed" },
    { id:"6.2.12", regex:/haveibeenpwned|pwnedpasswords|breached.?password/i, confidence:"high", note:"Breached password check detected" },
    { id:"6.5.3", regex:/secrets\.token|uuid4\(\)|nanoid|randomBytes/i, confidence:"medium", note:"Secure token generation detected" },
    { id:"6.5.8", regex:/totp|speakeasy|otplib|google.?authenticator|authenticator.?app/i, confidence:"high", note:"TOTP/MFA authenticator detected" },
    // NOTE: old "2.5.4" default credential check removed — its real 5.0.0
    // equivalent (6.4.1) is a Manual/documentation requirement, not SAST-checkable.
  ],
  "Session Management": [
    { id:"7.2.4", regex:/session\.regenerate|regenerateId|rotate.*session|session\.reset/i, confidence:"medium", note:"Session regeneration on login detected" },
    { id:"7.4.1", regex:/session\.destroy|session\.invalidate|clearCookie|logout.*session/i, confidence:"medium", note:"Session invalidation on logout detected" },
    { id:"9.1.1", regex:/jwt\.sign|jsonwebtoken|hs256|rs256|es256|RS256/i, confidence:"medium", note:"Self-contained token signing detected" },
    { id:"9.1.2", regex:/stateless|jwt.*bearer|bearer.*jwt/i, confidence:"medium", note:"Stateless token usage detected" },
  ],
  "Web Frontend Security": [
    { id:"3.3.1", regex:/[Ss]ecure\s*[:=]\s*true|secure:\s*true|httponly.*secure/i, confidence:"high", note:"Secure cookie flag detected" },
    { id:"3.3.4", regex:/[Hh]ttp[Oo]nly\s*[:=]\s*true|httpOnly:\s*true/i, confidence:"high", note:"HttpOnly cookie flag detected" },
    { id:"3.3.2", regex:/[Ss]ame[Ss]ite\s*[:=]\s*["']?(strict|lax)/i, confidence:"high", note:"SameSite cookie attribute detected" },
    { id:"3.4.1", regex:/strict.?transport.?security|HSTS|max-age=\d+.*includeSubDomains/i, confidence:"high", note:"HSTS header detected" },
    { id:"3.4.3", regex:/content.?security.?policy|CSP.*header|helmet\.contentSecurityPolicy/i, confidence:"high", note:"CSP header detected" },
    { id:"3.4.6", regex:/x.?frame.?options|frame.?ancestors|frameguard/i, confidence:"high", note:"Clickjacking protection detected" },
    { id:"3.4.5", regex:/referrer.?policy|Referrer-Policy/i, confidence:"high", note:"Referrer-Policy header detected" },
  ],
  "Authorization": [
    { id:"8.2.1", regex:/least.?privilege|rbac|role.?based|permission|authorize|isAdmin/i, confidence:"medium", note:"Access control / RBAC detected" },
    { id:"8.2.2", regex:/idor|object.?level|resource.?owner|ownership.?check/i, confidence:"medium", note:"Object-level access control detected" },
  ],
  "Encoding and Sanitization": [
    { id:"1.2.4", regex:/parameterized|prepared.?statement|sequelize\.|knex\.|typeorm|hibernate|\.query\(.*\?/i, confidence:"high", note:"Parameterized queries / ORM detected" },
    { id:"1.2.1", regex:/escape.?html|htmlencode|DOMPurify|sanitize.?html|xss|encodeURI/i, confidence:"high", note:"XSS protection / output encoding detected" },
    { id:"1.5.2", regex:/json\.parse|yaml\.safe_load|defusedxml|safe_load/i, confidence:"medium", note:"Safe deserialization detected" },
    { id:"1.3.6", regex:/ssrf|allowed.?host|validate.*url|urllib\.parse|URL\.parse/i, confidence:"medium", note:"SSRF protection detected" },
    { id:"1.3.2", regex:/eval\s*\(|new\s+Function\s*\(/i, confidence:"low", note:"Dangerous eval usage — review needed" },
    { id:"1.2.5", regex:/shell.?escape|parameterized.*command|child_process.*exec/i, confidence:"medium", note:"Command injection protection detected" },
  ],
  "Validation and Business Logic": [
    { id:"2.2.1", regex:/allowlist|whitelist|positive.?validation|joi\.|zod\.|yup\.|validator\./i, confidence:"high", note:"Input validation library detected" },
  ],
  "Cryptography": [
    { id:"11.3.2", regex:/AES.256|AES.128|aes-256-gcm|aes-128-gcm|ChaCha20|RSA.2048/i, confidence:"high", note:"Approved encryption algorithm detected" },
    { id:"11.3.1", regex:/md5|sha1(?!\d)|ecb.?mode/i, confidence:"low", note:"Weak cryptographic algorithm detected — review needed" },
    { id:"11.5.1", regex:/secrets\.token_hex|os\.urandom|crypto\.randomBytes|SecureRandom|getRandomValues/i, confidence:"high", note:"CSPRNG detected" },
    { id:"11.3.4", regex:/iv\s*=|nonce\s*=|initialization.?vector|gcm|GCM/i, confidence:"medium", note:"Encryption IV/nonce usage detected" },
  ],
  "Data Protection": [
    { id:"14.2.3", regex:/encrypt.*sensitive|sensitive.*encrypt|AES.*data|encrypt.*pii|pii.*encrypt/i, confidence:"medium", note:"Sensitive data encryption detected" },
    { id:"14.3.3", regex:/localStorage\.remove|sessionStorage\.clear|clearStorage/i, confidence:"medium", note:"Browser storage cleanup detected" },
  ],
  "Security Logging and Error Handling": [
    { id:"16.5.3", regex:/try\s*\{[\s\S]*?catch|except\s+\w+|rescue\s+\w+/i, confidence:"high", note:"Exception handling detected" },
    { id:"16.2.5", regex:/log\.(?!password|secret|token|key)/i, confidence:"medium", note:"Logging present — verify sensitive data excluded" },
  ],
  "Configuration": [
    { id:"13.4.2", regex:/debug\s*[:=]\s*false|NODE_ENV.*production|FLASK_DEBUG.*0/i, confidence:"medium", note:"Debug mode disabled detected" },
  ],
  "File Handling": [
    { id:"5.3.2", regex:/path\.basename|path\.join|os\.path|sanitize.*path|pathTraversal/i, confidence:"medium", note:"Path traversal protection detected" },
    { id:"5.2.1", regex:/max.?file.?size|content.?length.*limit|MAX_SIZE|fileSizeLimit/i, confidence:"medium", note:"File size limit detected" },
    { id:"5.3.1", regex:/upload.*outside.*root|secure.*upload.*dir|UPLOAD_FOLDER/i, confidence:"medium", note:"Secure file storage detected" },
  ],
};
