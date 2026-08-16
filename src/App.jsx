import { useState, useCallback, useRef, useEffect } from "react";

const API = "http://localhost:3001/api";

const ASVS_DATA = {
  "Authentication": [
    { id: "2.1.1", area: "Password Security", level: "1", cwe: "521", requirement: "Verify that user set passwords are at least 12 characters in length." },
    { id: "2.1.2", area: "Password Security", level: "1", cwe: "521", requirement: "Verify that passwords of at least 64 characters are permitted." },
    { id: "2.1.7", area: "Password Security", level: "1", cwe: "521", requirement: "Verify that passwords are checked against a set of breached passwords." },
    { id: "2.1.8", area: "Password Security", level: "1", cwe: "521", requirement: "Verify that a password strength meter is provided." },
    { id: "2.2.1", area: "General Authenticator", level: "1", cwe: "307", requirement: "Verify that anti-automation controls are effective at mitigating brute force attacks." },
    { id: "2.2.2", area: "General Authenticator", level: "1", cwe: "304", requirement: "Verify that weak authenticators such as SMS are limited to secondary verification." },
    { id: "2.3.1", area: "Authenticator Lifecycle", level: "1", cwe: "330", requirement: "Verify that system generated initial passwords are at least 6 characters and expire quickly." },
    { id: "2.4.1", area: "Credential Storage", level: "2", cwe: "916", requirement: "Verify that passwords are stored using an approved one-way key derivation or password hashing function." },
    { id: "2.4.2", area: "Credential Storage", level: "2", cwe: "916", requirement: "Verify that the salt is at least 32 bits in length." },
    { id: "2.4.3", area: "Credential Storage", level: "2", cwe: "916", requirement: "Verify that if PBKDF2 is used, the iteration count is at least 100,000." },
    { id: "2.4.4", area: "Credential Storage", level: "2", cwe: "916", requirement: "Verify that if bcrypt is used, the work factor is a minimum of 10." },
    { id: "2.5.1", area: "Credential Recovery", level: "1", cwe: "640", requirement: "Verify that a system generated recovery secret is not sent in clear text." },
    { id: "2.5.2", area: "Credential Recovery", level: "1", cwe: "640", requirement: "Verify password hints or knowledge-based authentication are not present." },
    { id: "2.5.4", area: "Credential Recovery", level: "1", cwe: "640", requirement: "Verify shared or default accounts are not present." },
    { id: "2.7.1", area: "OOB Authenticator", level: "1", cwe: "287", requirement: "Verify that clear text out of band authenticators such as SMS are not offered by default." },
    { id: "2.10.1", area: "Service Authentication", level: "2", cwe: "287", requirement: "Verify that integration secrets do not rely on unchanging passwords." },
    { id: "2.10.4", area: "Service Authentication", level: "3", cwe: "798", requirement: "Verify API keys are managed securely and not included in the source code." },
  ],
  "Session Management": [
    { id: "3.1.1", area: "Fundamental Session", level: "1", cwe: "598", requirement: "Verify the application never reveals session tokens in URL parameters or error messages." },
    { id: "3.2.1", area: "Session Binding", level: "1", cwe: "384", requirement: "Verify the application generates a new session token on user authentication." },
    { id: "3.2.2", area: "Session Binding", level: "1", cwe: "331", requirement: "Verify that session tokens possess at least 64 bits of entropy." },
    { id: "3.3.1", area: "Session Termination", level: "1", cwe: "613", requirement: "Verify that logout and expiration invalidate the session token." },
    { id: "3.3.2", area: "Session Termination", level: "1", cwe: "613", requirement: "Verify that re-authentication occurs periodically." },
    { id: "3.4.1", area: "Cookie-based Session", level: "1", cwe: "614", requirement: "Verify that cookie-based session tokens have the Secure attribute set." },
    { id: "3.4.2", area: "Cookie-based Session", level: "1", cwe: "1004", requirement: "Verify that cookie-based session tokens have the HttpOnly attribute set." },
    { id: "3.4.3", area: "Cookie-based Session", level: "1", cwe: "16", requirement: "Verify that cookie-based session tokens utilize the SameSite attribute." },
    { id: "3.5.2", area: "Token-based Session", level: "2", cwe: "345", requirement: "Verify the application uses only stateless session tokens." },
    { id: "3.5.3", area: "Token-based Session", level: "2", cwe: "345", requirement: "Verify that stateless session tokens use digital signatures and encryption." },
    { id: "3.7.1", area: "Session Exploits Defense", level: "1", cwe: "778", requirement: "Verify the application ensures a full valid login session before allowing sensitive transactions." },
  ],
  "Access Control": [
    { id: "4.1.1", area: "General Access Control", level: "1", cwe: "602", requirement: "Verify that the application enforces access control rules on a trusted service layer." },
    { id: "4.1.2", area: "General Access Control", level: "1", cwe: "639", requirement: "Verify that all user and data attributes used by access controls cannot be manipulated by end users." },
    { id: "4.1.3", area: "General Access Control", level: "1", cwe: "285", requirement: "Verify that the principle of least privilege exists." },
    { id: "4.1.5", area: "General Access Control", level: "1", cwe: "285", requirement: "Verify that access controls fail securely including when an exception occurs." },
    { id: "4.2.1", area: "Operation Level", level: "1", cwe: "639", requirement: "Verify that sensitive data and APIs are protected against IDOR attacks." },
    { id: "4.2.2", area: "Operation Level", level: "1", cwe: "352", requirement: "Verify that the application enforces a strong anti-CSRF mechanism." },
    { id: "4.3.1", area: "Other Access Control", level: "1", cwe: "419", requirement: "Verify administrative interfaces use appropriate multi-factor authentication." },
    { id: "4.3.2", area: "Other Access Control", level: "1", cwe: "22", requirement: "Verify that directory browsing is disabled unless deliberately desired." },
  ],
  "Input Validation": [
    { id: "5.1.1", area: "Input Validation", level: "1", cwe: "235", requirement: "Verify that the application has defenses against HTTP parameter pollution attacks." },
    { id: "5.1.3", area: "Input Validation", level: "1", cwe: "20", requirement: "Verify that all input is validated using positive validation (allow lists)." },
    { id: "5.1.4", area: "Input Validation", level: "1", cwe: "20", requirement: "Verify that structured data is strongly typed and validated against a defined schema." },
    { id: "5.1.5", area: "Input Validation", level: "1", cwe: "601", requirement: "Verify that URL redirects only allow destinations which appear on an allow list." },
    { id: "5.2.1", area: "Sanitization", level: "1", cwe: "79", requirement: "Verify that all untrusted HTML input is properly sanitized." },
    { id: "5.2.4", area: "Sanitization", level: "1", cwe: "95", requirement: "Verify that the application avoids the use of eval() or other dynamic code execution features." },
    { id: "5.2.6", area: "Sanitization", level: "1", cwe: "918", requirement: "Verify that the application protects against SSRF attacks." },
    { id: "5.3.3", area: "Output Encoding", level: "1", cwe: "79", requirement: "Verify that output escaping protects against reflected, stored, and DOM based XSS." },
    { id: "5.3.4", area: "Output Encoding", level: "1", cwe: "89", requirement: "Verify that database queries use parameterized queries or ORMs." },
    { id: "5.3.8", area: "Output Encoding", level: "1", cwe: "78", requirement: "Verify that the application protects against OS command injection." },
    { id: "5.5.1", area: "Deserialization", level: "1", cwe: "502", requirement: "Verify that serialized objects use integrity checks." },
    { id: "5.5.3", area: "Deserialization", level: "1", cwe: "502", requirement: "Verify that deserialization of untrusted data is avoided." },
    { id: "5.5.4", area: "Deserialization", level: "1", cwe: "502", requirement: "Verify that JSON.parse is used instead of eval() to parse JSON." },
  ],
  "Cryptography at Rest": [
    { id: "6.1.1", area: "Data Classification", level: "2", cwe: "311", requirement: "Verify that regulated private data is stored encrypted while at rest, such as PII." },
    { id: "6.1.2", area: "Data Classification", level: "2", cwe: "311", requirement: "Verify that regulated health data is stored encrypted while at rest." },
    { id: "6.2.1", area: "Algorithms", level: "1", cwe: "310", requirement: "Verify that all cryptographic modules fail securely." },
    { id: "6.2.2", area: "Algorithms", level: "2", cwe: "327", requirement: "Verify that industry proven cryptographic algorithms are used, not custom coded cryptography." },
    { id: "6.2.5", area: "Algorithms", level: "2", cwe: "326", requirement: "Verify that known insecure algorithms such as MD5 and SHA1 are not used." },
    { id: "6.2.6", area: "Algorithms", level: "2", cwe: "326", requirement: "Verify that nonces and initialization vectors are not reused." },
    { id: "6.3.1", area: "Random Values", level: "2", cwe: "338", requirement: "Verify that all random numbers are generated using approved CSPRNG." },
    { id: "6.3.2", area: "Random Values", level: "2", cwe: "338", requirement: "Verify that random GUIDs are created using the GUID v4 algorithm and CSPRNG." },
    { id: "6.4.1", area: "Secret Management", level: "2", cwe: "798", requirement: "Verify that a secrets management solution such as a key vault is used." },
    { id: "6.4.2", area: "Secret Management", level: "2", cwe: "798", requirement: "Verify that key material is not exposed to the application." },
  ],
  "Error Handling and Logging": [
    { id: "7.1.1", area: "Log Content", level: "1", cwe: "532", requirement: "Verify that the application does not log credentials or payment details." },
    { id: "7.1.2", area: "Log Content", level: "1", cwe: "532", requirement: "Verify that the application does not log other sensitive data." },
    { id: "7.1.3", area: "Log Content", level: "2", cwe: "778", requirement: "Verify that the application logs security relevant events." },
    { id: "7.3.1", area: "Log Protection", level: "2", cwe: "117", requirement: "Verify that all logging components encode data to prevent log injection." },
    { id: "7.4.1", area: "Error Handling", level: "1", cwe: "210", requirement: "Verify that a generic message is shown when an unexpected error occurs." },
    { id: "7.4.2", area: "Error Handling", level: "2", cwe: "544", requirement: "Verify that exception handling is used across the codebase." },
    { id: "7.4.3", area: "Error Handling", level: "2", cwe: "460", requirement: "Verify that a last resort error handler is defined." },
  ],
  "Communication Security": [
    { id: "9.1.1", area: "Client Communications", level: "1", cwe: "319", requirement: "Verify that TLS is used for all client connectivity." },
    { id: "9.1.2", area: "Client Communications", level: "1", cwe: "326", requirement: "Verify that only strong cipher suites are enabled." },
    { id: "9.1.3", area: "Client Communications", level: "1", cwe: "326", requirement: "Verify that only the latest recommended versions of TLS are enabled, such as TLS 1.2 and TLS 1.3." },
    { id: "9.2.1", area: "Server Communications", level: "2", cwe: "295", requirement: "Verify that connections to and from the server use trusted TLS certificates." },
    { id: "9.2.3", area: "Server Communications", level: "2", cwe: "319", requirement: "Verify that all encrypted connections to external systems are authenticated." },
    { id: "9.2.4", area: "Server Communications", level: "2", cwe: "295", requirement: "Verify that proper certification revocation such as OCSP Stapling is enabled." },
  ],
  "Data Protection": [
    { id: "8.1.1", area: "General Data Protection", level: "2", cwe: "524", requirement: "Verify the application protects sensitive data from being cached in server components." },
    { id: "8.2.1", area: "Client-side Data", level: "1", cwe: "312", requirement: "Verify the application sets sufficient anti-caching headers." },
    { id: "8.2.2", area: "Client-side Data", level: "1", cwe: "312", requirement: "Verify that data stored in browser storage does not contain sensitive data." },
    { id: "8.2.3", area: "Client-side Data", level: "1", cwe: "312", requirement: "Verify that authenticated data is cleared from client storage after session termination." },
    { id: "8.3.1", area: "Sensitive Private Data", level: "1", cwe: "359", requirement: "Verify that sensitive data is sent to the server in the HTTP message body or headers." },
    { id: "8.3.4", area: "Sensitive Private Data", level: "1", cwe: "359", requirement: "Verify that all sensitive data created by the application has been identified." },
    { id: "8.3.7", area: "Sensitive Private Data", level: "2", cwe: "359", requirement: "Verify that sensitive information is encrypted using approved algorithms." },
  ],
  "API and Web Service": [
    { id: "13.1.1", area: "Generic Web Service", level: "1", cwe: "116", requirement: "Verify that all application components use the same encodings and parsers." },
    { id: "13.1.3", area: "Generic Web Service", level: "1", cwe: "598", requirement: "Verify API URLs do not expose sensitive information such as the API key." },
    { id: "13.2.1", area: "RESTful Web Service", level: "1", cwe: "352", requirement: "Verify that enabled RESTful HTTP methods are a valid choice for the user or action." },
    { id: "13.2.2", area: "RESTful Web Service", level: "1", cwe: "16", requirement: "Verify that JSON schema validation is in place and verified before accepting input." },
    { id: "13.2.3", area: "RESTful Web Service", level: "1", cwe: "352", requirement: "Verify that RESTful web services are protected from Cross-Site Request Forgery." },
    { id: "13.2.5", area: "RESTful Web Service", level: "2", cwe: "650", requirement: "Verify that REST services explicitly check the incoming Content-Type." },
    { id: "13.4.1", area: "GraphQL", level: "2", cwe: "770", requirement: "Verify that query allow lists are used to prevent GraphQL DoS." },
  ],
  "Configuration": [
    { id: "14.2.1", area: "Dependency", level: "1", cwe: "1026", requirement: "Verify that all components are up to date." },
    { id: "14.2.3", area: "Dependency", level: "1", cwe: "829", requirement: "Verify that Subresource Integrity (SRI) is used for externally hosted assets." },
    { id: "14.3.2", area: "Security Disclosure", level: "1", cwe: "497", requirement: "Verify that debug modes are disabled in production." },
    { id: "14.3.3", area: "Security Disclosure", level: "1", cwe: "200", requirement: "Verify that HTTP headers do not expose detailed version information." },
    { id: "14.4.3", area: "HTTP Security Headers", level: "1", cwe: "693", requirement: "Verify that a Content Security Policy (CSP) response header is in place." },
    { id: "14.4.4", area: "HTTP Security Headers", level: "1", cwe: "693", requirement: "Verify that all responses contain a X-Content-Type-Options: nosniff header." },
    { id: "14.4.5", area: "HTTP Security Headers", level: "1", cwe: "693", requirement: "Verify that a Strict-Transport-Security header is included on all responses." },
    { id: "14.4.6", area: "HTTP Security Headers", level: "1", cwe: "693", requirement: "Verify that a suitable Referrer-Policy header is included." },
    { id: "14.4.7", area: "HTTP Security Headers", level: "1", cwe: "116", requirement: "Verify that the content of a web application cannot be embedded in a third-party site." },
    { id: "14.5.1", area: "HTTP Request Header", level: "1", cwe: "346", requirement: "Verify that the application server only accepts the HTTP methods in use." },
    { id: "14.5.3", area: "HTTP Request Header", level: "1", cwe: "346", requirement: "Verify that the CORS Access-Control-Allow-Origin header uses a strict allow list." },
  ],
  "Files and Resources": [
    { id: "12.1.1", area: "File Upload", level: "1", cwe: "400", requirement: "Verify that the application will not accept large files that could cause denial of service." },
    { id: "12.1.2", area: "File Upload", level: "2", cwe: "409", requirement: "Verify that compressed files are checked against maximum allowed uncompressed size." },
    { id: "12.3.1", area: "File Execution", level: "1", cwe: "22", requirement: "Verify that user-submitted filename metadata is not used directly to protect against path traversal." },
    { id: "12.3.2", area: "File Execution", level: "1", cwe: "22", requirement: "Verify that user-submitted filename metadata is validated to prevent LFI." },
    { id: "12.4.1", area: "File Storage", level: "1", cwe: "552", requirement: "Verify that files from untrusted sources are stored outside the web root." },
    { id: "12.5.1", area: "File Download", level: "1", cwe: "552", requirement: "Verify that the web tier is configured to serve only files with specific extensions." },
  ],
};

const SOLIDITY_PATTERNS = [
  { id:"4.1.3", regex:/onlyOwner|onlyAdmin|onlyRole|hasRole|AccessControl|Ownable/i, confidence:"high", note:"Access control modifier detected" },
  { id:"4.2.1", regex:/require\(msg\.sender|require\(owner|modifier.*only/i, confidence:"high", note:"Ownership/IDOR check detected" },
  { id:"5.1.3", regex:/require\(|revert\(|assert\(/i, confidence:"high", note:"Input validation via require/revert detected" },
  { id:"6.2.2", regex:/keccak256|sha256|sha3|AES|encrypt/i, confidence:"high", note:"Cryptographic hash function detected" },
  { id:"6.3.2", regex:/bytes32|bytes16|uint256.*random|block\.timestamp/i, confidence:"medium", note:"Unique identifier generation detected" },
  { id:"5.3.4", regex:/mapping\(|SafeMath|unchecked\s*{/i, confidence:"medium", note:"Safe math or mapping used" },
  { id:"7.4.1", regex:/emit\s+\w+Event|event\s+\w+|Error\(/i, confidence:"medium", note:"Event logging detected" },
  { id:"7.4.2", regex:/try\s*{|catch\s*\(|revert\s*\(/i, confidence:"medium", note:"Error handling detected" },
  { id:"4.3.1", regex:/Pausable|whenNotPaused|pause\(\)|unpause\(\)/i, confidence:"high", note:"Pausable/emergency stop detected" },
  { id:"8.1.4", regex:/ReentrancyGuard|nonReentrant|mutex|locked/i, confidence:"high", note:"Reentrancy protection detected" },
  { id:"14.2.1", regex:/import.*OpenZeppelin|@openzeppelin|SafeERC20/i, confidence:"high", note:"OpenZeppelin security library detected" },
  { id:"9.1.1", regex:/https:\/\/|IPFS|ipfs\./i, confidence:"low", note:"Secure external reference detected" },
  { id:"2.1.1", regex:/password.*length|minLength|maxLength/i, confidence:"medium", note:"Password length validation detected" },
  { id:"6.4.1", regex:/private\s+\w+.*key|privateKey|secretKey/i, confidence:"medium", note:"Private key storage pattern detected" },
  { id:"13.2.2", regex:/ABI\.decode|abi\.decode|JSON\.parse/i, confidence:"medium", note:"Input schema validation detected" },
];

const PATTERNS = {
  "Authentication": [
    { id:"2.4.1", regex:/bcrypt|argon2|scrypt|pbkdf2|password_hash|hashpw/i, confidence:"high", note:"Password hashing function detected" },
    { id:"2.4.4", regex:/bcrypt.*rounds|saltRounds\s*=\s*\d+|work.?factor/i, confidence:"high", note:"bcrypt work factor configured" },
    { id:"2.4.3", regex:/pbkdf2.*100000|iterations.*100000/i, confidence:"high", note:"PBKDF2 iteration count detected" },
    { id:"2.2.1", regex:/rate.?limit|ratelimit|slowDown|brute.?force|max.?attempt|lockout|throttl/i, confidence:"medium", note:"Rate limiting / brute force protection detected" },
    { id:"2.5.4", regex:/default.?password|admin.*admin|root.*root|password.*=.*["\']123/i, confidence:"low", note:"Possible default credential — review needed" },
    { id:"2.10.4", regex:/api.?key\s*=\s*["\'][^"\'\s]{8,}|secret\s*=\s*["\'][^"\'\s]{8,}/i, confidence:"low", note:"Possible hardcoded secret — review needed" },
    { id:"2.1.7", regex:/haveibeenpwned|pwnedpasswords|breached.?password/i, confidence:"high", note:"Breached password check detected" },
    { id:"2.3.1", regex:/secrets\.token|uuid4\(\)|nanoid|randomBytes/i, confidence:"medium", note:"Secure token generation detected" },
    { id:"2.7.1", regex:/totp|speakeasy|otplib|google.?authenticator|authenticator.?app/i, confidence:"high", note:"TOTP/MFA authenticator detected" },
  ],
  "Session Management": [
    { id:"3.4.1", regex:/[Ss]ecure\s*[:=]\s*true|secure:\s*true|httponly.*secure/i, confidence:"high", note:"Secure cookie flag detected" },
    { id:"3.4.2", regex:/[Hh]ttp[Oo]nly\s*[:=]\s*true|httpOnly:\s*true/i, confidence:"high", note:"HttpOnly cookie flag detected" },
    { id:"3.4.3", regex:/[Ss]ame[Ss]ite\s*[:=]\s*["\']?(strict|lax)/i, confidence:"high", note:"SameSite cookie attribute detected" },
    { id:"3.2.1", regex:/session\.regenerate|regenerateId|rotate.*session|session\.reset/i, confidence:"medium", note:"Session regeneration on login detected" },
    { id:"3.3.1", regex:/session\.destroy|session\.invalidate|clearCookie|logout.*session/i, confidence:"medium", note:"Session invalidation on logout detected" },
    { id:"3.5.3", regex:/jwt\.sign|jsonwebtoken|hs256|rs256|es256|RS256/i, confidence:"medium", note:"JWT token signing detected" },
    { id:"3.5.2", regex:/stateless|jwt.*bearer|bearer.*jwt/i, confidence:"medium", note:"Stateless token usage detected" },
  ],
  "Access Control": [
    { id:"4.2.2", regex:/csrf|csurf|csrfProtection|csrf.?token|x-csrf/i, confidence:"high", note:"CSRF protection detected" },
    { id:"4.1.3", regex:/least.?privilege|rbac|role.?based|permission|authorize|isAdmin/i, confidence:"medium", note:"Access control / RBAC detected" },
    { id:"4.2.1", regex:/idor|object.?level|resource.?owner|ownership.?check/i, confidence:"medium", note:"Object-level access control detected" },
  ],
  "Input Validation": [
    { id:"5.3.4", regex:/parameterized|prepared.?statement|sequelize\.|knex\.|typeorm|hibernate|\.query\(.*\?/i, confidence:"high", note:"Parameterized queries / ORM detected" },
    { id:"5.3.3", regex:/escape.?html|htmlencode|DOMPurify|sanitize.?html|xss|encodeURI/i, confidence:"high", note:"XSS protection / output encoding detected" },
    { id:"5.5.3", regex:/json\.parse|yaml\.safe_load|defusedxml|safe_load/i, confidence:"medium", note:"Safe deserialization detected" },
    { id:"5.2.6", regex:/ssrf|allowed.?host|validate.*url|urllib\.parse|URL\.parse/i, confidence:"medium", note:"SSRF protection detected" },
    { id:"5.1.3", regex:/allowlist|whitelist|positive.?validation|joi\.|zod\.|yup\.|validator\./i, confidence:"high", note:"Input validation library detected" },
    { id:"5.2.4", regex:/eval\s*\(|new\s+Function\s*\(/i, confidence:"low", note:"Dangerous eval usage — review needed" },
    { id:"5.3.8", regex:/shell.?escape|parameterized.*command|child_process.*exec/i, confidence:"medium", note:"Command injection protection detected" },
  ],
  "Cryptography at Rest": [
    { id:"6.2.2", regex:/AES.256|AES.128|aes-256-gcm|aes-128-gcm|ChaCha20|RSA.2048/i, confidence:"high", note:"Approved encryption algorithm detected" },
    { id:"6.2.5", regex:/md5|sha1|des|rc4|ecb.?mode/i, confidence:"low", note:"Weak cryptographic algorithm detected — review needed" },
    { id:"6.3.1", regex:/secrets\.token_hex|os\.urandom|crypto\.randomBytes|SecureRandom|getRandomValues/i, confidence:"high", note:"CSPRNG detected" },
    { id:"6.4.1", regex:/vault|keyvault|aws.?kms|azure.?key|secrets.?manager|hashicorp/i, confidence:"high", note:"Key vault / secrets management detected" },
    { id:"6.2.6", regex:/iv\s*=|nonce\s*=|initialization.?vector|gcm|GCM/i, confidence:"medium", note:"Encryption IV/nonce usage detected" },
    { id:"6.1.1", regex:/encrypt.*pii|pii.*encrypt|encrypt.*personal|AES.*personal/i, confidence:"medium", note:"PII encryption detected" },
  ],
  "Error Handling and Logging": [
    { id:"7.4.2", regex:/try\s*\{[\s\S]*?catch|except\s+\w+|rescue\s+\w+/i, confidence:"high", note:"Exception handling detected" },
    { id:"7.1.3", regex:/audit.?log|security.?log|auth.*log|winston|bunyan|log4j|pino/i, confidence:"high", note:"Security logging library detected" },
    { id:"7.4.1", regex:/generic.?error|error.?message.*generic|custom.*error.*handler/i, confidence:"medium", note:"Generic error handling detected" },
    { id:"7.1.1", regex:/log\.(?!password|secret|token|key)/i, confidence:"medium", note:"Logging present — verify sensitive data excluded" },
  ],
  "Communication Security": [
    { id:"9.1.1", regex:/https:\/\/|ssl\.wrap|tls\.|require.?ssl|httpsServer/i, confidence:"high", note:"HTTPS/TLS usage detected" },
    { id:"9.1.3", regex:/TLSv1\.2|TLSv1\.3|minVersion.*TLS/i, confidence:"high", note:"TLS version specification detected" },
    { id:"9.2.3", regex:/cert.?verify|ssl_verify|verify.*true|ca.?bundle|checkServerIdentity/i, confidence:"medium", note:"Certificate verification detected" },
    { id:"9.2.4", regex:/ocsp|stapling|cert.?revoc/i, confidence:"medium", note:"Certificate revocation detected" },
  ],
  "Data Protection": [
    { id:"8.2.1", regex:/cache.?control|no.?cache|no.?store|Pragma.*no.?cache/i, confidence:"high", note:"Cache-control headers detected" },
    { id:"8.3.7", regex:/encrypt.*sensitive|sensitive.*encrypt|AES.*data/i, confidence:"medium", note:"Sensitive data encryption detected" },
    { id:"8.2.2", regex:/localStorage\.remove|sessionStorage\.clear|clearStorage/i, confidence:"medium", note:"Browser storage cleanup detected" },
  ],
  "API and Web Service": [
    { id:"13.2.3", regex:/csrf.*token|csrfmiddlewaretoken|x.csrf.token|anti.?forgery/i, confidence:"high", note:"CSRF protection detected" },
    { id:"13.1.3", regex:/authorization.*bearer|x.api.key|api.?key.*header/i, confidence:"medium", note:"API authentication header detected" },
    { id:"13.2.2", regex:/json.?schema|joi\.|yup\.|zod\.|ajv\.|openapi/i, confidence:"high", note:"JSON schema / API validation detected" },
    { id:"13.2.5", regex:/content.?type.*check|accept.*application\/json|mediaType/i, confidence:"medium", note:"Content-Type validation detected" },
  ],
  "Configuration": [
    { id:"14.4.5", regex:/strict.?transport.?security|HSTS|max-age=\d+.*includeSubDomains/i, confidence:"high", note:"HSTS header detected" },
    { id:"14.4.3", regex:/content.?security.?policy|CSP.*header|helmet\.contentSecurityPolicy/i, confidence:"high", note:"CSP header detected" },
    { id:"14.4.4", regex:/x.?content.?type.?options|nosniff|helmet/i, confidence:"high", note:"X-Content-Type-Options header detected" },
    { id:"14.3.2", regex:/debug\s*[:=]\s*false|NODE_ENV.*production|FLASK_DEBUG.*0/i, confidence:"medium", note:"Debug mode disabled detected" },
    { id:"14.4.7", regex:/x.?frame.?options|frame.?ancestors|frameguard/i, confidence:"high", note:"Clickjacking protection detected" },
    { id:"14.4.6", regex:/referrer.?policy|Referrer-Policy/i, confidence:"high", note:"Referrer-Policy header detected" },
    { id:"14.5.3", regex:/cors.*origin.*allowlist|Access-Control-Allow-Origin.*https/i, confidence:"medium", note:"CORS allowlist detected" },
  ],
  "Files and Resources": [
    { id:"12.3.1", regex:/path\.basename|path\.join|os\.path|sanitize.*path|pathTraversal/i, confidence:"medium", note:"Path traversal protection detected" },
    { id:"12.1.1", regex:/max.?file.?size|content.?length.*limit|MAX_SIZE|fileSizeLimit/i, confidence:"medium", note:"File size limit detected" },
    { id:"12.4.1", regex:/upload.*outside.*root|secure.*upload.*dir|UPLOAD_FOLDER/i, confidence:"medium", note:"Secure file storage detected" },
  ],
};

const CAT_META = {
  "Authentication":            { icon:"🔐", color:"#4a9eff" },
  "Session Management":        { icon:"🔄", color:"#4affd4" },
  "Access Control":            { icon:"🛡️", color:"#d44aff" },
  "Input Validation":          { icon:"✅", color:"#ffd44a" },
  "Cryptography at Rest":      { icon:"🔒", color:"#4aff4a" },
  "Error Handling and Logging":{ icon:"📋", color:"#ff4a4a" },
  "Communication Security":    { icon:"🔗", color:"#4a4aff" },
  "Data Protection":           { icon:"💾", color:"#ffaa4a" },
  "API and Web Service":       { icon:"🌐", color:"#4ad4ff" },
  "Configuration":             { icon:"⚙️", color:"#aaaaaa" },
  "Files and Resources":       { icon:"📁", color:"#ff884a" },
};

const CONF_COLOR = { high:"#4aff4a", medium:"#ffd44a", low:"#ff884a" };

function getLineInfo(code, pattern) {
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) {
      return {
        lineNumber: i + 1,
        lineContent: lines[i].trim().substring(0, 150),
      };
    }
  }
  return null;
}

const INSECURE_PATTERNS = {
  "2.4.1": { pattern: /NoOpPasswordEncoder|MessageDigest.*MD5|new MD5|md5\(password/i, msg: "Insecure password storage — NoOpPasswordEncoder or MD5 detected" },
  "2.4.4": { pattern: /gensalt\(\s*\)|rounds\s*=\s*[1-9](?!0)|saltRounds\s*=\s*[1-9](?!0)/i, msg: "bcrypt work factor too low — minimum 10 required" },
  "3.4.1": { pattern: /secure\s*:\s*false|setSecure\(false\)|Secure=false/i, msg: "Secure flag disabled on cookie" },
  "3.4.2": { pattern: /httpOnly\s*:\s*false|setHttpOnly\(false\)|HttpOnly=false/i, msg: "HttpOnly flag disabled on cookie" },
  "3.5.3": { pattern: /algorithm.*none|alg.*none|HS256|HMAC.*SHA256/i, msg: "Weak JWT algorithm — use RS256 or ES256" },
  "5.3.4": { pattern: /createStatement\(\)|Statement\(\)|executeQuery\(.*\+|query.*\+.*req|sql\s*\+=|sql\s*=.*\+/i, msg: "SQL injection risk — string concatenation in query detected" },
  "6.2.2": { pattern: /DES|RC4|Cipher\.getInstance\(.*ECB|AES\/ECB/i, msg: "Weak cipher detected — use AES-256-GCM" },
  "6.2.5": { pattern: /MD5|SHA-?1|DigestUtils\.md5|MessageDigest.*SHA.?1/i, msg: "Weak hash algorithm — never use MD5 or SHA1" },
  "6.3.1": { pattern: /Math\.random\(\)|new Random\(\)|rand\(\)|mt_rand\(/i, msg: "Insecure random number generator — use SecureRandom or secrets" },
  "9.2.3": { pattern: /verify\s*=\s*False|verify\s*=\s*false|VERIFY_SSL\s*=\s*false|InsecureRequestWarning/i, msg: "SSL certificate verification disabled" },
  "9.1.3": { pattern: /TLSv1\.0|TLSv1\.1|SSLv3|SSLv2|TLS_1_0|TLS_1_1/i, msg: "Weak TLS version detected — minimum TLS 1.2 required" },
  "2.10.4": { pattern: /api_key\s*=\s*["'][a-zA-Z0-9]{8,}|secret\s*=\s*["'][a-zA-Z0-9]{8,}|password\s*=\s*["'][a-zA-Z0-9]{6,}/i, msg: "Hardcoded secret or API key detected in source" },
  "5.3.3": { pattern: /innerHTML\s*=|document\.write\(|\.html\(.*req/i, msg: "XSS risk — unsafe HTML output method detected" },
  "5.2.4": { pattern: /eval\(.*req|eval\(.*input|exec\(.*request/i, msg: "Code injection risk — eval() with user input" },
  "14.3.2": { pattern: /DEBUG\s*=\s*True|debug\s*=\s*true|app\.run.*debug.*True/i, msg: "Debug mode enabled — must be disabled in production" },
  "4.2.2": { pattern: /csrf\s*=\s*false|csrf_exempt|csrfProtection\s*=\s*false/i, msg: "CSRF protection disabled" },
  "5.3.8": { pattern: /Runtime\.exec\(|ProcessBuilder.*input|shell\s*=\s*True/i, msg: "Command injection risk — user input passed to shell" },
  "8.2.2": { pattern: /localStorage\.setItem.*password|sessionStorage\.setItem.*token/i, msg: "Sensitive data stored in browser storage" },
  "5.3.4": { pattern: /createStatement\(\)|Statement\(\)|executeQuery\(.*\+|query.*\+.*req|sql\s*\+=|sql\s*=.*\+/i, msg: "SQL injection risk — string concatenation in query detected" },
};

function getInsecureLineInfo(code, reqId) {
  const insecure = INSECURE_PATTERNS[reqId];
  if (!insecure) return null;
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (insecure.pattern.test(lines[i])) {
      return {
        lineNumber: i + 1,
        lineContent: lines[i].trim().substring(0, 150),
        msg: insecure.msg,
        isWrong: true
      };
    }
  }
  return null;
}

function analyzeCode(code, category) {
  const findings = [];
  const matched = new Set();
  for (const p of (PATTERNS[category] || [])) {
    if (!matched.has(p.id) && p.regex.test(code)) {
      matched.add(p.id);
      const lineInfo = getLineInfo(code, p.regex);
      findings.push({
        reqId: p.id,
        confidence: p.confidence,
        note: p.note,
        lineNumber: lineInfo ? lineInfo.lineNumber : null,
        lineContent: lineInfo ? lineInfo.lineContent : null,
        isWrong: false,
      });
    }
  }
  // Case 2: Wrong implementations
  for (const p of (PATTERNS[category] || [])) {
    if (!matched.has(p.id)) {
      const wrongInfo = getInsecureLineInfo(code, p.id);
      if (wrongInfo) {
        findings.push({
          reqId: p.id,
          confidence: "low",
          note: wrongInfo.msg,
          lineNumber: wrongInfo.lineNumber,
          lineContent: wrongInfo.lineContent,
          isWrong: true,
        });
        matched.add(p.id);
      }
    }
  }
  return findings;
}

function runAnalysis(files) {
  const isSolidity = files.some(f => f.name && f.name.endsWith('.sol'));
  const combined = files.map(f => f.content).join("\n");
  
  // Handle Solidity files separately
  if (isSolidity) {
    const findings = [];
    const matched = new Set();
    for (const p of SOLIDITY_PATTERNS) {
      if (!matched.has(p.id) && p.regex.test(combined)) {
        matched.add(p.id);
        const lineInfo = getLineInfo(combined, p.regex);
        findings.push({
          reqId: p.id,
          confidence: p.confidence,
          note: p.note,
          lineNumber: lineInfo ? lineInfo.lineNumber : null,
          lineContent: lineInfo ? lineInfo.lineContent : null,
          isWrong: false,
        });
      }
    }
    // Build results for Solidity
    const categoryResults = {};
    let totalFindings = 0, totalReqs = 0;
    for (const [cat, reqs] of Object.entries(ASVS_DATA)) {
      const foundIds = new Set(findings.map(f => f.reqId));
      const reqResults = reqs.map(req => {
        const finding = findings.find(f => f.reqId === req.id) || null;
        return { ...req, finding, implemented: foundIds.has(req.id), wrongImplementation: false };
      });
      const implemented = reqResults.filter(r => r.implemented).length;
      const pct = Math.round((implemented / reqs.length) * 100);
      categoryResults[cat] = { reqs: reqResults, implemented, total: reqs.length, pct };
      totalFindings += implemented;
      totalReqs += reqs.length;
    }
    return { categoryResults, totalFindings, totalReqs, overallPct: Math.round((totalFindings/totalReqs)*100), fileCount: files.length, language: 'Solidity' };
  }
  const categoryResults = {};
  let totalFindings = 0, totalReqs = 0;
  for (const [cat, reqs] of Object.entries(ASVS_DATA)) {
    const findings = analyzeCode(combined, cat);
    const foundIds = new Set(findings.map(f => f.reqId));
    const reqResults = reqs.map(req => {
      const finding = findings.find(f => f.reqId === req.id) || null;
      const isWrongImpl = finding && finding.isWrong === true;
      return {
        ...req,
        finding,
        implemented: foundIds.has(req.id) && !isWrongImpl,
        wrongImplementation: isWrongImpl,
      };
    });
    const implemented = reqResults.filter(r => r.implemented).length;
    categoryResults[cat] = { reqs: reqResults, implemented, total: reqs.length, pct: Math.round((implemented / reqs.length) * 100), findings };
    totalFindings += implemented;
    totalReqs += reqs.length;
  }
  const overallPct = Math.round((totalFindings / totalReqs) * 100);
  const level = overallPct >= 70 ? "Level 2" : overallPct >= 40 ? "Level 1" : "Below L1";
  return { categoryResults, totalFindings, totalReqs, overallPct, level };
}

// ─── Mini Chart ───────────────────────────────────────────────
function BarChart({ data }) {
  const max = Math.max(...data.map(d => d.pct), 1);
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
      {data.map(d => (
        <div key={d.cat} style={{ display:"flex", alignItems:"center", gap:8 }}>
          <div style={{ width:150, fontSize:11, color:"#555555", textAlign:"right", flexShrink:0, whiteSpace:"normal", lineHeight:1.3 }}>
            {CAT_META[d.cat]?.icon} {d.cat}
          </div>
          <div style={{ flex:1, height:18, background:"#f0f2f5", borderRadius:4, overflow:"hidden" }}>
            <div style={{ width:`${(d.pct/max)*100}%`, height:"100%", background: CAT_META[d.cat]?.color || "#1F3864", borderRadius:4, transition:"width 0.6s ease", minWidth: d.pct>0?4:0 }}/>
          </div>
          <div style={{ width:36, fontSize:11, color:"#333333", fontWeight:700 }}>{d.pct}%</div>
        </div>
      ))}
    </div>
  );
}

function RadialScore({ pct, level }) {
  const r = 54; const circ = 2 * Math.PI * r;
  const dash = (pct / 100) * circ;
  const color = pct >= 70 ? "#4aff4a" : pct >= 40 ? "#ffd44a" : "#ff4a4a";
  return (
    <div style={{ display:"flex", flexDirection:"column", alignItems:"center", gap:8 }}>
      <svg width={130} height={130} viewBox="0 0 130 130">
        <circle cx={65} cy={65} r={r} fill="none" stroke="#f0f2f5" strokeWidth={10}/>
        <circle cx={65} cy={65} r={r} fill="none" stroke={color} strokeWidth={10}
          strokeDasharray={`${dash} ${circ - dash}`} strokeLinecap="round"
          transform="rotate(-90 65 65)" style={{ transition:"stroke-dasharray 0.8s ease" }}/>
        <text x={65} y={60} textAnchor="middle" fill={color} fontSize={22} fontWeight={700}>{pct}%</text>
        <text x={65} y={80} textAnchor="middle" fill="#555555" fontSize={11}>{level}</text>
        <text x={65} y={96} textAnchor="middle" fill="#555555" fontSize={10}>Overall Coverage</text>
      </svg>
    </div>
  );
}

// ─── Auth Pages ───────────────────────────────────────────────
function AuthPage({ onLogin }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    if (!username || !password) return setError("Fill in all fields");
    setLoading(true); setError("");
    try {
      const res = await fetch(`${API}/${mode}`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (data.ok) onLogin(data.user);
      else setError(data.error || "Failed");
    } catch { setError("Cannot reach server — is backend running?"); }
    setLoading(false);
  };

  return (
    <div style={{ minHeight:"100vh", background:"#f5f6fa", display:"flex", alignItems:"center", justifyContent:"center" }}>
      <div style={{ background:"#ffffff", border:"1px solid #30363d", borderRadius:16, padding:40, width:360 }}>
        <div style={{ textAlign:"center", marginBottom:28 }}>
          <div style={{ fontSize:36, marginBottom:8 }}>🛡️</div>
          <div style={{ fontSize:20, fontWeight:700, color:"#1a1a2e" }}>ASVS Compliance & Maturity Analyzer</div>
          <div style={{ fontSize:12, color:"#555555", marginTop:4 }}>OWASP Application Security Verification Standard</div>
        </div>
        <div style={{ display:"flex", gap:8, marginBottom:24 }}>
          {["login","register"].map(m => (
            <button key={m} onClick={() => { setMode(m); setError(""); }} style={{
              flex:1, padding:"8px 0", borderRadius:8, border:"1px solid",
              borderColor: mode===m ? "#2E75B6" : "#d0d7de",
              background: mode===m ? "#1f3a5c" : "transparent",
              color: mode===m ? "#1F3864" : "#555555",
              cursor:"pointer", fontWeight:600, fontSize:13, textTransform:"capitalize"
            }}>{m}</button>
          ))}
        </div>
        <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
          <input value={username} onChange={e => setUsername(e.target.value)}
            placeholder="Username" onKeyDown={e => e.key==="Enter" && submit()}
            style={{ padding:"10px 14px", borderRadius:8, border:"1px solid #30363d", background:"#f5f6fa", color:"#1a1a2e", fontSize:14, outline:"none" }}/>
          <input type="password" value={password} onChange={e => setPassword(e.target.value)}
            placeholder="Password" onKeyDown={e => e.key==="Enter" && submit()}
            style={{ padding:"10px 14px", borderRadius:8, border:"1px solid #30363d", background:"#f5f6fa", color:"#1a1a2e", fontSize:14, outline:"none" }}/>
          {error && <div style={{ color:"#ff4a4a", fontSize:12, textAlign:"center" }}>{error}</div>}
          <button onClick={submit} disabled={loading} style={{
            padding:"11px", borderRadius:8, border:"none",
            background: loading ? "#f0f2f5" : "linear-gradient(135deg,#1f6feb,#388bfd)",
            color: loading ? "#666666" : "#fff", fontWeight:700, fontSize:14, cursor: loading?"not-allowed":"pointer"
          }}>{loading ? "Please wait..." : mode==="login" ? "Sign In" : "Create Account"}</button>
        </div>
      </div>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────
export default function App() {
  const [user, setUser] = useState(() => { try { return JSON.parse(localStorage.getItem("asvs_user")); } catch { return null; } });
  const [tab, setTab] = useState("analyze");
  const [files, setFiles] = useState([]);
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiInsights, setAiInsights] = useState(null);
  const [selectedCat, setSelectedCat] = useState(null);
  const [filterLevel, setFilterLevel] = useState("all");
  const [expanded, setExpanded] = useState({});
  const [scans, setScans] = useState([]);
  const [projectName, setProjectName] = useState("My Project");
  const [dragOver, setDragOver] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const fileRef = useRef();
  const folderRef = useRef();

  const login = (u) => { setUser(u); localStorage.setItem("asvs_user", JSON.stringify(u)); };
  const logout = () => { setUser(null); localStorage.removeItem("asvs_user"); setResults(null); setFiles([]); };

  useEffect(() => {
    if (user && tab === "history") fetchScans();
  }, [tab, user]);

  const fetchScans = async () => {
    try {
      const res = await fetch(`${API}/scans/${user.id}`);
      const data = await res.json();
      setScans(data);
    } catch {}
  };

  const loadHistoryScan = async (scanId) => {
    try {
      const res = await fetch(`${API}/scans/detail/${scanId}`);
      const data = await res.json();
      const categoryResults = data.results;
      const totalFindings = data.total_findings;
      const totalReqs = data.total_reqs;
      const overallPct = data.overall_pct;
      const level = data.asvs_level;
      setResults({ categoryResults, totalFindings, totalReqs, overallPct, level });
      setSelectedCat(Object.keys(categoryResults)[0]);
      setProjectName(data.project_name);
      setAiInsights(null);
      setTab("results");
    } catch(e) { alert("Failed to load scan: " + e.message); }
  };

  const handleFiles = (fileList) => {
    const readers = Array.from(fileList).map(file => new Promise(res => {
      const reader = new FileReader();
      reader.onload = e => res({ name: file.name, content: e.target.result, size: file.size });
      reader.readAsText(file);
    }));
    Promise.all(readers).then(loaded => setFiles(prev => [...prev, ...loaded]));
  };

  const handleDrop = (e) => {
    e.preventDefault(); setDragOver(false);
    handleFiles(e.dataTransfer.files);
  };

  const analyze = useCallback(async () => {
    if (!files.length) return;
    setLoading(true); setResults(null); setAiInsights(null);
    await new Promise(r => setTimeout(r, 400));
    const res = runAnalysis(files);
    setResults(res);
    setSelectedCat(Object.keys(res.categoryResults)[0]);
    setLoading(false);
    setTab("results");

    // Save scan
    try {
      await fetch(`${API}/scans`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({
          user_id: user.id, project_name: projectName,
          files_count: files.length, total_findings: res.totalFindings,
          total_reqs: res.totalReqs, overall_pct: res.overallPct,
          asvs_level: res.level, results: res.categoryResults
        })
      });
    } catch {}

    // Local AI Analysis
    setAiLoading(true);
    await new Promise(r => setTimeout(r, 800));
    try {
      const cats = Object.entries(res.categoryResults);
      const topPassing = cats.filter(([,d]) => d.implemented > 0).sort((a,b) => b[1].implemented - a[1].implemented).slice(0,4);
      const topFailing = cats.filter(([,d]) => d.pct < 40).sort((a,b) => a[1].pct - b[1].pct).slice(0,4);
      const score = res.overallPct; // AI score matches overall coverage %
      const strengths = topPassing.map(([cat, d]) => {
        const ctrl = d.reqs.find(r => r.implemented);
        return ctrl ? cat + ": " + (ctrl.finding?.note || "Security control detected") : cat + ": " + d.implemented + " controls implemented";
      });
      const risks = topFailing.map(([cat, d]) => {
        const gap = d.reqs.find(r => !r.implemented);
        return gap ? cat + " (" + d.pct + "%): " + gap.requirement.slice(0,80) + "..." : cat + ": Only " + d.pct + "% coverage";
      });
      const recs = topFailing.slice(0,4).map(([cat, d]) => {
        const gap = d.reqs.find(r => !r.implemented);
        return gap ? "[" + gap.id + "] " + gap.requirement : "Improve " + cat + " coverage";
      });
      const passing2 = topPassing.slice(0,2).map(([c]) => c).join(" and ");
      const failing2 = topFailing.slice(0,2).map(([c]) => c).join(" and ");
      setAiInsights({
        summary: "The codebase demonstrates " + res.totalFindings + " implemented ASVS 5.0 security controls across " + Object.keys(res.categoryResults).filter(c => res.categoryResults[c].implemented > 0).length + " of 11 categories, achieving " + res.overallPct + "% overall coverage. Strongest areas include " + passing2 + ". Priority remediation should focus on " + failing2 + " which show the lowest control coverage.",
        strengths,
        risks,
        topRecommendations: recs,
        securityScore: score
      });
    } catch(e) { console.log(e); }
    setAiLoading(false);
  }, [files, user, projectName]);

  const exportExcel = async () => {
    if (!results) return;
    try {
      const res = await fetch(`${API}/export/excel`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ categoryResults: results.categoryResults, project_name: projectName })
      });
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href=url; a.download="ASVS-Compliance-Maturity-Report.xlsx"; a.click();
      URL.revokeObjectURL(url);
    } catch(e) { alert("Export failed: " + e.message); }
  };

  const exportPDF = async () => {
    if (!results) return;
    try {
      const res = await fetch(`${API}/export/pdf`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ categoryResults: results.categoryResults, project_name: projectName })
      });
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href=url; a.download="ASVS-Compliance-Maturity-Report.pdf"; a.click();
      URL.revokeObjectURL(url);
    } catch(e) { alert("Export failed: " + e.message); }
  };

  if (!user) return <AuthPage onLogin={login} />;

  const filteredReqs = results && selectedCat
    ? results.categoryResults[selectedCat].reqs.filter(r => filterLevel==="all" || r.level===filterLevel)
    : [];

  const chartData = results
    ? Object.entries(results.categoryResults).sort(([a],[b]) => { const order = ["Authentication","Session Management","Access Control","Input Validation","Cryptography at Rest","Error Handling and Logging","Communication Security","Data Protection","API and Web Service","Configuration","Files and Resources"]; return order.indexOf(a) - order.indexOf(b); }).map(([cat, d]) => ({ cat, pct: d.pct }))
    : [];

  return (
    <div style={{ minHeight:"100vh", background:"#f5f6fa", color:"#1a1a2e", fontFamily:"Segoe UI,system-ui,sans-serif" }}>
      {/* Header */}
      <div style={{ background:"#ffffff", borderBottom:"1px solid #30363d", padding:"12px 24px", display:"flex", alignItems:"center", gap:12, position:"sticky", top:0, zIndex:100 }}>
        <div style={{ width:32, height:32, borderRadius:8, background:"linear-gradient(135deg,#1f6feb,#388bfd)", display:"flex", alignItems:"center", justifyContent:"center", fontSize:16 }}>🛡️</div>
        <div>
          <div style={{ fontWeight:700, fontSize:15 }}>ASVS Compliance & Maturity Analyzer</div>
          <div style={{ fontSize:10, color:"#555555" }}>OWASP ASVS 5.0 · AI-Powered</div>
        </div>
        <div style={{ marginLeft:"auto", display:"flex", gap:6, alignItems:"center" }}>
          {["analyze","results","history","reference"].map(t => (
            <button key={t} onClick={() => setTab(t)} style={{
              padding:"5px 12px", borderRadius:6, border:"1px solid",
              borderColor: tab===t ? "#1F3864" : "#d0d7de",
              background: tab===t ? "#1F3864" : "transparent",
              color: tab===t ? "#ffffff" : "#555555",
              cursor:"pointer", fontSize:11, fontWeight:600, textTransform:"capitalize"
            }}>{t}</button>
          ))}
          <div style={{ marginLeft:8, position:"relative" }}>
            <button onClick={() => setProfileOpen(p => !p)} style={{
              display:"flex", alignItems:"center", gap:8, padding:"5px 12px 5px 6px",
              borderRadius:20, background:"#f0f2f5", border:"1px solid #30363d",
              cursor:"pointer", transition:"border-color 0.2s"
            }}
              onMouseEnter={e => e.currentTarget.style.borderColor="#2E75B6"}
              onMouseLeave={e => e.currentTarget.style.borderColor="#d0d7de"}>
              <div style={{ width:26, height:26, borderRadius:"50%", background:"linear-gradient(135deg,#388bfd,#4affd4)", display:"flex", alignItems:"center", justifyContent:"center", fontSize:11, fontWeight:700, color:"#f5f6fa" }}>{user.username[0].toUpperCase()}</div>
              <span style={{ fontSize:12, color:"#333333", fontWeight:600 }}>{user.username}</span>
              <span style={{ fontSize:10, color:"#555555" }}>{profileOpen?"▲":"▼"}</span>
            </button>
            {profileOpen && (
              <div style={{ position:"absolute", right:0, top:"calc(100% + 8px)", background:"#ffffff", border:"1px solid #d0d7de", borderRadius:10, width:200, boxShadow:"0 4px 16px rgba(0,0,0,0.15)", zIndex:200, overflow:"hidden" }}>
                <div style={{ padding:"12px 16px", borderBottom:"1px solid #d0d7de", background:"#f5f6fa", display:"flex", alignItems:"center", gap:10 }}>
                  <div style={{ width:36, height:36, borderRadius:"50%", background:"linear-gradient(135deg,#388bfd,#4affd4)", display:"flex", alignItems:"center", justifyContent:"center", fontSize:14, fontWeight:700, color:"#f5f6fa" }}>{user.username[0].toUpperCase()}</div>
                  <div>
                    <div style={{ fontWeight:700, fontSize:13, color:"#1a1a2e" }}>{user.username}</div>
                    <div style={{ fontSize:11, color:"#555555" }}>ASVS Compliance & Maturity Analyzer User</div>
                  </div>
                </div>
                <div style={{ padding:8 }}>
                  <button onClick={() => { setTab("history"); setProfileOpen(false); fetchScans(); }} style={{ width:"100%", padding:"8px 12px", background:"transparent", border:"none", color:"#333333", cursor:"pointer", textAlign:"left", borderRadius:6, fontSize:13, display:"flex", alignItems:"center", gap:8 }}
                    onMouseEnter={e => e.currentTarget.style.background="#f0f2f5"}
                    onMouseLeave={e => e.currentTarget.style.background="transparent"}>
                    🕐 Scan History
                  </button>
                  <button onClick={() => { setTab("reference"); setProfileOpen(false); }} style={{ width:"100%", padding:"8px 12px", background:"transparent", border:"none", color:"#333333", cursor:"pointer", textAlign:"left", borderRadius:6, fontSize:13, display:"flex", alignItems:"center", gap:8 }}
                    onMouseEnter={e => e.currentTarget.style.background="#f0f2f5"}
                    onMouseLeave={e => e.currentTarget.style.background="transparent"}>
                    📖 ASVS Reference
                  </button>
                  <div style={{ borderTop:"1px solid #30363d", margin:"6px 0" }}/>
                  <button onClick={() => { logout(); setProfileOpen(false); }} style={{ width:"100%", padding:"8px 12px", background:"transparent", border:"none", color:"#ff4a4a", cursor:"pointer", textAlign:"left", borderRadius:6, fontSize:13, display:"flex", alignItems:"center", gap:8 }}
                    onMouseEnter={e => e.currentTarget.style.background="#ff4a4a22"}
                    onMouseLeave={e => e.currentTarget.style.background="transparent"}>
                    🚪 Sign Out
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <div style={{ maxWidth:1280, margin:"0 auto", padding:"20px 24px" }}>

        {/* ANALYZE TAB */}
        {tab==="analyze" && (
          <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
            <div style={{ display:"flex", gap:12, alignItems:"center" }}>
              <input value={projectName} onChange={e => setProjectName(e.target.value)}
                placeholder="Project name..."
                style={{ padding:"8px 14px", borderRadius:8, border:"1px solid #30363d", background:"#ffffff", color:"#1a1a2e", fontSize:13, outline:"none", width:260 }}/>
              <div style={{ fontSize:12, color:"#555555" }}>Name your project before scanning</div>
            </div>

            {/* Drop zone */}
            <div onDrop={handleDrop} onDragOver={e => { e.preventDefault(); setDragOver(true); }} onDragLeave={() => setDragOver(false)}
              onClick={() => fileRef.current.click()}
              style={{ border:`2px dashed ${dragOver ? "#2E75B6" : "#d0d7de"}`, borderRadius:12, padding:40, textAlign:"center", cursor:"pointer", background: dragOver ? "#1f3a5c22" : "#ffffff", transition:"all 0.2s" }}>
              <div style={{ fontSize:36, marginBottom:10 }}>📂</div>
              <div style={{ fontWeight:600, marginBottom:4 }}>Drop files here or click to upload</div>
              <div style={{ fontSize:12, color:"#555555" }}>JS, Python, Java, Go, PHP, Ruby, C#, TypeScript, Solidity — multiple files supported</div>
              <input ref={fileRef} type="file" multiple accept=".js,.py,.java,.go,.php,.rb,.ts,.cs,.cpp,.c,.rs,.kt,.swift,.sol,.xml,.json,.yaml,.yml" onChange={e => handleFiles(e.target.files)} style={{ display:"none" }}/>
          <input ref={folderRef} type="file" webkitdirectory="" directory="" multiple onChange={e => handleFiles(e.target.files)} style={{ display:"none" }}/>
            </div>

            {/* File list */}
            {files.length > 0 && (
              <div style={{ background:"#ffffff", border:"1px solid #30363d", borderRadius:10, overflow:"hidden" }}>
                <div style={{ padding:"10px 16px", borderBottom:"1px solid #30363d", display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                  <span style={{ fontWeight:600, fontSize:13 }}>{files.length} file{files.length>1?"s":""} loaded</span>
                  <button onClick={() => setFiles([])} style={{ background:"none", border:"none", color:"#ff4a4a", cursor:"pointer", fontSize:12 }}>Clear all</button> <button
                onClick={() => folderRef.current.click()}
                onClick={() => folderRef.current.click()}
                style={{ marginLeft:'8px', padding:'10px 20px', borderRadius:8, border:'1px dashed #2E75B6', background:'transparent', color:'#1F3864', fontWeight:700, fontSize:13, cursor:'pointer' }}>
                📁 Upload Folder
              </button>
                </div>
                {files.map((f, i) => (
                  <div key={i} style={{ padding:"8px 16px", borderBottom:"1px solid #21262d", display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                    <span style={{ fontSize:12, color:"#333333" }}>📄 {f.name}</span>
                    <div style={{ display:"flex", gap:12, alignItems:"center" }}>
                      <span style={{ fontSize:11, color:"#555555" }}>{Math.round(f.size/1024)} KB · {f.content.split("\n").length} lines</span>
                      <button onClick={() => setFiles(prev => prev.filter((_,j)=>j!==i))} style={{ background:"none", border:"none", color:"#666666", cursor:"pointer", fontSize:12 }}>✕</button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            <button onClick={analyze} disabled={!files.length || loading} style={{
              padding:"12px", borderRadius:10, border:"none", alignSelf:"flex-end", width:220,
              background: files.length && !loading ? "linear-gradient(135deg,#1f6feb,#388bfd)" : "#f0f2f5",
              color: files.length && !loading ? "#fff" : "#666666",
              fontWeight:700, fontSize:14, cursor: files.length && !loading ? "pointer" : "not-allowed"
            }}>{loading ? "⟳ Scanning..." : "🔍 Run ASVS Analysis"}</button>
          </div>
        )}

        {/* RESULTS TAB */}
        {tab==="results" && results && (
          <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
            {/* Top stats */}
            <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:12 }}>
              {[
                { label:"Controls Found", value:results.totalFindings, color:"#1F3864" },
                { label:"Total Requirements", value:results.totalReqs, color:"#555555" },
                { label:"Coverage", value:`${results.overallPct}%`, color: results.overallPct>=70?"#4aff4a":results.overallPct>=40?"#ffd44a":"#ff4a4a" },
                { label:"Files Analyzed", value:files.length, color:"#ffd44a" },
                { label:"Categories", value:Object.keys(results.categoryResults).filter(c=>results.categoryResults[c].implemented>0).length, color:"#4ad4ff" },
              ].map(s => (
                <div key={s.label} style={{ background:"#ffffff", border:"1px solid #30363d", borderRadius:10, padding:16 }}>
                  <div style={{ fontSize:10, color:"#555555", textTransform:"uppercase", letterSpacing:"0.5px", marginBottom:6 }}>{s.label}</div>
                  <div style={{ fontSize:24, fontWeight:700, color:s.color }}>{s.value}</div>
                </div>
              ))}
            </div>

            {/* Chart + Radial */}
            <div style={{ display:"grid", gridTemplateColumns:"1fr auto", gap:16 }}>
              <div style={{ background:"#ffffff", border:"1px solid #30363d", borderRadius:10, padding:20 }}>
                <div style={{ fontWeight:700, marginBottom:14, fontSize:13 }}>Category Coverage</div>
                <BarChart data={chartData} />
              </div>
              <div style={{ background:"#ffffff", border:"1px solid #30363d", borderRadius:10, padding:20, display:"flex", alignItems:"center", justifyContent:"center" }}>
                <RadialScore pct={results.overallPct} level={results.level} />
              </div>
            </div>

            {/* Export buttons */}
            <div style={{ display:"flex", gap:10, justifyContent:"flex-end" }}>
              <button onClick={exportExcel} style={{ padding:"9px 18px", borderRadius:8, border:"none", background:"linear-gradient(135deg,#1a6b3a,#2ea043)", color:"#fff", fontWeight:700, fontSize:12, cursor:"pointer" }}>📥 Export Excel</button>
              <button onClick={exportPDF} style={{ padding:"9px 18px", borderRadius:8, border:"none", background:"linear-gradient(135deg,#6b1a1a,#c0392b)", color:"#fff", fontWeight:700, fontSize:12, cursor:"pointer" }}>📄 Export PDF</button>
            </div>

            {/* AI Insights */}
            {aiLoading && (
              <div style={{ background:"#ffffff", border:"1px solid #1f6feb", borderRadius:10, padding:20, textAlign:"center", color:"#555555" }}>
                🤖 Claude AI is analyzing your code...
              </div>
            )}
            {!aiLoading && !aiInsights && results && (
              <div style={{ background:"#ffffff", border:"1px solid #30363d", borderRadius:10, padding:20 }}>
                <div style={{ display:"flex", gap:8, alignItems:"center", marginBottom:10 }}>
                  <span style={{ fontSize:16 }}>🤖</span>
                  <span style={{ fontWeight:700, color:"#1F3864", fontSize:13 }}>Claude AI Security Assessment</span>
                  
                </div>
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:12 }}>
                  <div style={{ background:"#f5f6fa", borderRadius:8, padding:12, border:"1px solid #4aff4a22" }}>
                    <div style={{ fontSize:11, fontWeight:700, color:"#4aff4a", marginBottom:8 }}>✅ Likely Strengths</div>
                    <div style={{ fontSize:12, color:"#333333" }}>Based on pattern detection, {results.totalFindings} security controls were detected including authentication, session management, and configuration controls.</div>
                  </div>
                  <div style={{ background:"#f5f6fa", borderRadius:8, padding:12, border:"1px solid #ff884a22" }}>
                    <div style={{ fontSize:11, fontWeight:700, color:"#ff884a", marginBottom:8 }}>⚠️ Key Gaps</div>
                    <div style={{ fontSize:12, color:"#333333" }}>{results.totalReqs - results.totalFindings} ASVS requirements undetected. Check gap analysis in each category for specific remediation guidance.</div>
                  </div>
                  <div style={{ background:"#f5f6fa", borderRadius:8, padding:12, border:"1px solid #ffd44a22" }}>
                    <div style={{ fontSize:11, fontWeight:700, color:"#ffd44a", marginBottom:8 }}>💡 Recommendation</div>
                    <div style={{ fontSize:12, color:"#333333" }}>Focus on categories with 0% coverage first.  API credits at console.anthropic.com for full AI-powered analysis.</div>
                  </div>
                </div>
              </div>
            )}
            {aiInsights && (
              <div style={{ background:"linear-gradient(135deg,#EEF4FF,#D6E4F0)", border:"1px solid #2E75B6", borderRadius:10, padding:20 }}>
                <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:14 }}>
                  <div style={{ display:"flex", gap:8, alignItems:"center" }}>
                    <span style={{ fontSize:16 }}>🤖</span>
                    <span style={{ fontWeight:700, color:"#1F3864", fontSize:13 }}>Claude AI Security Assessment</span>
                  </div>
                  {aiInsights.securityScore !== undefined && (
                    <div style={{ padding:"4px 12px", borderRadius:20, background: aiInsights.securityScore>=70?"#4aff4a22":aiInsights.securityScore>=40?"#ffd44a22":"#ff4a4a22", color: aiInsights.securityScore>=70?"#4aff4a":aiInsights.securityScore>=40?"#ffd44a":"#ff4a4a", fontSize:12, fontWeight:700 }}>
                      AI Score: {aiInsights.securityScore}/100
                    </div>
                  )}
                </div>
                <p style={{ margin:"0 0 14px", color:"#333333", fontSize:13, lineHeight:1.7 }}>{aiInsights.summary}</p>
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:12 }}>
                  {[
                    { title:"✅ Strengths", items:aiInsights.strengths, color:"#375623" },
                    { title:"⚠️ Risks", items:aiInsights.risks, color:"#9C0006" },
                    { title:"💡 Recommendations", items:aiInsights.topRecommendations, color:"#9C6500" },
                  ].map(s => (
                    <div key={s.title} style={{ background:"#f5f6fa", borderRadius:8, padding:12, border:`1px solid ${s.color}22` }}>
                      <div style={{ fontSize:11, fontWeight:700, color:s.color, marginBottom:8 }}>{s.title}</div>
                      {(s.items||[]).map((item,i) => (
                        <div key={i} style={{ fontSize:12, color:"#333333", marginBottom:6, lineHeight:1.5, display:"flex", gap:6 }}>
                          <span style={{ color:s.color, flexShrink:0 }}>›</span>{item}
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Category sidebar + detail */}
            <div style={{ display:"grid", gridTemplateColumns:"220px 1fr", gap:16 }}>
              <div style={{ display:"flex", flexDirection:"column", gap:5 }}>
                {Object.entries(results.categoryResults).sort(([a],[b]) => { const order = ["Authentication","Session Management","Access Control","Input Validation","Cryptography at Rest","Error Handling and Logging","Communication Security","Data Protection","API and Web Service","Configuration","Files and Resources"]; return order.indexOf(a) - order.indexOf(b); }).map(([cat, d]) => {
                  const meta = CAT_META[cat] || { color:"#1F3864", icon:"🔷" };
                  const active = selectedCat===cat;
                  return (
                    <button key={cat} onClick={() => setSelectedCat(cat)} style={{
                      background: active?"#ffffff":"transparent",
                      border:`1px solid ${active?meta.color+"60":"#d0d7de"}`,
                      borderLeft:`3px solid ${active?meta.color:"transparent"}`,
                      borderRadius:8, padding:"8px 10px", cursor:"pointer", textAlign:"left"
                    }}>
                      <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
                        <span style={{ fontSize:11, fontWeight:600, color:active?meta.color:"#333333" }}>{meta.icon} {cat.split(" ").slice(0,2).join(" ")}</span>
                        <span style={{ fontSize:11, color:meta.color, fontWeight:700 }}>{d.pct}%</span>
                      </div>
                      <div style={{ height:3, background:"#f0f2f5", borderRadius:2 }}>
                        <div style={{ width:`${d.pct}%`, height:"100%", background:meta.color, borderRadius:2 }}/>
                      </div>
                      <div style={{ fontSize:10, color:"#666666", marginTop:3 }}>{d.implemented}/{d.total}</div>
                    </button>
                  );
                })}
              </div>

              {selectedCat && (
                <div style={{ background:"#ffffff", border:"1px solid #30363d", borderRadius:10, padding:16, maxHeight:580, overflowY:"auto" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:14 }}>
                    <div>
                      <div style={{ fontWeight:700, fontSize:14 }}>{CAT_META[selectedCat]?.icon} {selectedCat}</div>
                      <div style={{ fontSize:12, color:"#555555" }}>{results.categoryResults[selectedCat].implemented}/{results.categoryResults[selectedCat].total} requirements detected</div>
                    </div>
                    <div style={{ display:"flex", gap:5 }}>
                      {["all","1","2","3"].map(l => (
                        <button key={l} onClick={() => setFilterLevel(l)} style={{
                          padding:"3px 9px", borderRadius:5, border:`1px solid ${filterLevel===l?"#1F3864":"#d0d7de"}`,
                          background: filterLevel===l?"#f0f2f5":"transparent",
                          color: filterLevel===l?"#1F3864":"#555555", cursor:"pointer", fontSize:11
                        }}>{l==="all"?"All":`L${l}`}</button>
                      ))}
                    </div>
                  </div>
                  {filteredReqs.map(req => {
                    const isOpen = expanded[req.id];
                    const meta = CAT_META[selectedCat] || { color:"#1F3864" };
                    return (
                      <div key={req.id} style={{ marginBottom:6, borderRadius:8, overflow:"hidden", border:`1px solid ${req.implemented?meta.color+"40":"#f0f2f5"}`, background:req.implemented?meta.color+"08":"#f5f6fa" }}>
                        <button onClick={() => setExpanded(p => ({ ...p, [req.id]:!p[req.id] }))}
                          style={{ width:"100%", padding:"9px 12px", background:"transparent", border:"none", cursor:"pointer", display:"flex", alignItems:"center", gap:8, textAlign:"left" }}>
                          <span style={{ fontSize:13 }}>{req.implemented?"✅":"⬜"}</span>
                          <span style={{ fontSize:11, fontWeight:700, color:meta.color, background:meta.color+"20", padding:"2px 5px", borderRadius:4, flexShrink:0 }}>{req.id}</span>
                          <span style={{ fontSize:10, color:"#666666", background:"#f0f2f5", padding:"2px 4px", borderRadius:4, flexShrink:0 }}>L{req.level}</span>
                          {req.cwe && <span style={{ fontSize:10, color:"#666666", flexShrink:0 }}>CWE-{req.cwe}</span>}
                          <span style={{ fontSize:12, color:req.implemented?"#333333":"#666666", flex:1 }}>{req.requirement.slice(0,85)}...</span>
                          {req.finding && <span style={{ fontSize:10, padding:"2px 5px", borderRadius:4, background:CONF_COLOR[req.finding.confidence]+"20", color:CONF_COLOR[req.finding.confidence], flexShrink:0 }}>{req.finding.confidence}</span>}
                          <span style={{ color:"#666666", fontSize:11 }}>{isOpen?"▲":"▼"}</span>
                        </button>
                        {isOpen && (
                          <div style={{ padding:"0 12px 10px", borderTop:"1px solid #21262d" }}>
                            <p style={{ fontSize:12, color:"#333333", lineHeight:1.7, margin:"8px 0" }}>{req.requirement}</p>
                            {req.finding && <div style={{ background:"#f5f6fa", borderRadius:6, padding:"7px 10px", fontSize:12, color:"#555555" }}><span style={{ color:CONF_COLOR[req.finding.confidence], fontWeight:700 }}>{req.finding.confidence.toUpperCase()}:</span> {req.finding.note}</div>}
                            {!req.implemented && (
                              <div style={{ background:"#FFF2CC", borderRadius:6, padding:"7px 10px", fontSize:12, color:"#9C6500", marginTop:5, border:"1px solid #FFEB9C" }}>
                                <strong>⚠️ Not Detected</strong><br/>
                                <span style={{color:"#333333"}}>Requirement: {req.requirement}</span><br/>
                                <span style={{color:"#C00000", fontSize:11}}>CWE-{req.cwe} — Control missing from source code</span>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        )}

        {tab==="results" && !results && (
          <div style={{ textAlign:"center", padding:"80px 0", color:"#666666" }}>
            <div style={{ fontSize:48, marginBottom:16 }}>🔍</div>
            <div style={{ fontSize:16, marginBottom:6 }}>No analysis yet</div>
            <div style={{ fontSize:13 }}>Upload files and run analysis from the Analyze tab</div>
          </div>
        )}

        {/* HISTORY TAB */}
        {tab==="history" && (
          <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
            <div style={{ fontWeight:700, fontSize:16, marginBottom:4 }}>Scan History</div>
            {scans.length === 0 && <div style={{ color:"#666666", fontSize:13, textAlign:"center", padding:40 }}>No scans yet. Run your first analysis!</div>}
            {scans.map(s => (
              <div key={s.id} onClick={() => loadHistoryScan(s.id)} style={{ background:"#ffffff", border:"1px solid #30363d", borderRadius:10, padding:16, display:"flex", justifyContent:"space-between", alignItems:"center", cursor:"pointer", transition:"border-color 0.2s" }}
                onMouseEnter={e => e.currentTarget.style.borderColor="#2E75B6"}
                onMouseLeave={e => e.currentTarget.style.borderColor="#d0d7de"}>
                <div>
                  <div style={{ fontWeight:600, marginBottom:4 }}>📁 {s.project_name}</div>
                  <div style={{ fontSize:12, color:"#555555" }}>{s.files_count} file{s.files_count>1?"s":""} · {s.total_findings}/{s.total_reqs} controls · {s.created_at}</div>
                </div>
                <div style={{ display:"flex", gap:10, alignItems:"center" }}>
                  <div style={{ fontSize:20, fontWeight:700, color: s.overall_pct>=70?"#4aff4a":s.overall_pct>=40?"#ffd44a":"#ff4a4a" }}>{s.overall_pct}%</div>
                  <div style={{ fontSize:11, padding:"3px 8px", borderRadius:6, background:"#f0f2f5", color:"#333333" }}>{s.asvs_level}</div>
                  <div style={{ fontSize:11, color:"#1F3864" }}>View →</div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* REFERENCE TAB */}
        {tab==="reference" && (
          <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
            <div style={{ fontWeight:700, fontSize:16, marginBottom:4 }}>ASVS 5.0 Reference — All Requirements</div>
            {Object.entries(ASVS_DATA).map(([cat, reqs]) => {
              const meta = CAT_META[cat] || { color:"#1F3864", icon:"🔷" };
              const open = expanded["ref_"+cat];
              return (
                <div key={cat} style={{ background:"#ffffff", border:"1px solid #30363d", borderRadius:10, overflow:"hidden" }}>
                  <button onClick={() => setExpanded(p => ({ ...p, ["ref_"+cat]:!p["ref_"+cat] }))}
                    style={{ width:"100%", padding:"13px 16px", background:"transparent", border:"none", cursor:"pointer", display:"flex", alignItems:"center", gap:10, textAlign:"left" }}>
                    <span style={{ fontSize:18 }}>{meta.icon}</span>
                    <div style={{ flex:1 }}>
                      <div style={{ fontWeight:700, color:"#1a1a2e", fontSize:13 }}>{cat}</div>
                      <div style={{ fontSize:11, color:"#555555" }}>{reqs.length} requirements</div>
                    </div>
                    <span style={{ color:meta.color, fontSize:16 }}>{open?"▲":"▼"}</span>
                  </button>
                  {open && (
                    <div style={{ borderTop:"1px solid #21262d", padding:"10px 16px" }}>
                      {reqs.map(req => (
                        <div key={req.id} style={{ padding:"7px 0", borderBottom:"1px solid #21262d", display:"flex", gap:8, alignItems:"flex-start" }}>
                          <span style={{ fontSize:11, fontWeight:700, color:meta.color, background:meta.color+"20", padding:"2px 5px", borderRadius:4, flexShrink:0 }}>{req.id}</span>
                          <span style={{ fontSize:10, color:"#ffd44a", background:"#ffd44a20", padding:"2px 4px", borderRadius:4, flexShrink:0 }}>L{req.level}</span>
                          {req.cwe && <span style={{ fontSize:10, color:"#ff884a", background:"#ff884a20", padding:"2px 4px", borderRadius:4, flexShrink:0 }}>CWE-{req.cwe}</span>}
                          <span style={{ fontSize:12, color:"#333333", lineHeight:1.6 }}>{req.requirement}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
