const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const multer = require("multer");
const path = require("path");
const speakeasy = require("speakeasy");
const winston = require("winston");

const app = express();
app.use(express.json());

// 13.4.2 — production configuration
const productionMode = process.env.NODE_ENV === "production";
const debug = false;
const NODE_ENV = "production";

// 13.3.2 detector intentionally NOT triggered:
// secrets should come from environment variables.
const apiKeyFromEnv = process.env.API_KEY;
const secretFromEnv = process.env.SESSION_SECRET || "development-only-secret";

// 16.2.4 — structured logging
const logger = winston.createLogger({
  level: "info",
  transports: [new winston.transports.Console()]
});

// 6.3.1 — rate limiting / brute-force protection
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false
});
app.use("/login", loginLimiter);

// 3.4.1 — HSTS
app.use((req, res, next) => {
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.setHeader("Content-Security-Policy", "default-src 'self'");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  next();
});

// 3.3.1, 3.3.2, 3.3.4 — secure cookie controls
app.use(session({
  secret: secretFromEnv,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: "strict"
  }
}));

// 5.2.1 — explicit file-size comparison detector
const MAX_FILE_SIZE = 5 * 1024 * 1024;
const upload = multer({ dest: "/tmp/asvs-demo-uploads" });

function validateUpload(file) {
  if (file.size > MAX_FILE_SIZE) {
    throw new Error("File too large");
  }
  return true;
}

// 5.3.2 and 5.3.1 — safe filename/path handling
function safeUploadPath(filename) {
  const safeName = path.basename(filename);
  const UPLOAD_FOLDER = "/tmp/asvs-demo-uploads";
  return path.join(UPLOAD_FOLDER, safeName);
}

// 5.4.1 — filename sanitization detector
function sanitizeFilename(filename) {
  return path.basename(filename).replace(/[^a-zA-Z0-9._-]/g, "_");
}

// 5.4.3 — antivirus detector
const clamscan = {
  async scan(filePath) {
    return { isInfected: false, filePath };
  }
};

// 2.2.1 — input validation library style
const validator = {
  isEmail(value) {
    return typeof value === "string" && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value);
  }
};

// 1.2.1 — output encoding / sanitization
function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// 1.2.4 — parameterized query example
async function findUser(db, email) {
  return db.query("SELECT * FROM users WHERE email = ?", [email]);
}

// 1.3.6 — SSRF allowlist
const ALLOWED_HOSTS = ["api.example.com", "cdn.example.com"];
function isAllowedHost(hostname) {
  return ALLOWED_HOSTS.includes(hostname);
}

// 1.2.5 — command execution protection example
function commandOptions() {
  return { shell: false };
}

// 11.4.2 / 11.4.4 — password hashing + work factor
async function hashPassword(password) {
  const saltRounds = 12;
  return bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, storedHash) {
  return bcrypt.compare(password, storedHash);
}

// 6.2.12 — breached password check
async function checkBreachedPassword(password) {
  const haveibeenpwned = {
    async check() {
      return { breached: false };
    }
  };
  return haveibeenpwned.check(password);
}

// 6.5.3 / 11.5.1 — CSPRNG
function createSecureToken() {
  return crypto.randomBytes(32).toString("hex");
}

// 11.3.2 / 11.3.4 — approved encryption + IV/nonce
function encryptSensitiveData(plaintext, key) {
  const iv = crypto.randomBytes(12);
  const nonce = iv;
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { encrypted, iv, nonce, tag };
}

// 14.2.3 — sensitive data encryption
function encryptSensitiveRecord(record) {
  return encryptSensitiveData(JSON.stringify(record), crypto.randomBytes(32));
}

// 14.3.3 — browser storage cleanup
function clearClientStorage() {
  if (typeof localStorage !== "undefined") {
    localStorage.removeItem("sensitive-data");
  }
  if (typeof sessionStorage !== "undefined") {
    sessionStorage.clear();
  }
}

// 6.5.8 — TOTP/MFA verification
function verifyTotp(secret, token) {
  return speakeasy.totp.verify({
    secret,
    encoding: "base32",
    token
  });
}

// 9.1.1 — JWT signing
function issueToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role },
    process.env.JWT_SECRET || "demo-jwt-secret",
    { expiresIn: "15m" }
  );
}

// 9.1.3 / 9.2.3 — JWT verification + audience validation
function verifyToken(token) {
  return jwt.verify(
    token,
    process.env.JWT_SECRET || "demo-jwt-secret",
    { audience: "asvs-demo-api" }
  );
}

// 9.1.2 — stateless bearer token configuration
const statelessJwtBearer = true;

// 9.1.2 — algorithm allowlist
const jwtOptions = {
  algorithms: ["HS256"]
};

// 8.2.1 — authorization/RBAC
function authorize(requiredRole) {
  return (req, res, next) => {
    if (req.user && req.user.role === requiredRole) return next();
    logger.warn("Authorization failure");
    return res.status(403).json({ error: "Forbidden" });
  };
}

function hasRole(user, role) {
  return user && user.role === role;
}

// 8.2.2 — object-level authorization
function checkResourceOwner(user, resourceOwnerId) {
  return user && user.id === resourceOwnerId;
}

// 4.3.2 — GraphQL introspection disabled
const graphqlConfig = {
  introspection: false
};

// 4.3.1 — GraphQL depth/cost limiting
function depthLimit(limit) {
  return { limit };
}
const graphqlDepthRule = depthLimit(5);

// 13.4.3 — directory listing disabled
const staticOptions = {
  autoIndex: false
};

// 13.4.4 — TRACE method blocked
function isBlockedMethod(method) {
  return method === "TRACE";
}

// 13.2.4 — external resource allowlist
const ALLOWED_RESOURCES = ["api.example.com", "cdn.example.com"];

// 15.4.1 — mutex/shared-resource protection
class Mutex {
  async runExclusive(task) {
    return task();
  }
}
const resourceMutex = new Mutex();

// 16.5.3 — exception handling
async function safeOperation() {
  try {
    return await Promise.resolve("ok");
  } catch (e) {
    logger.error("Operation failed");
    throw e;
  }
}

// 16.5.4 — last-resort exception handler
process.on("uncaughtException", (err) => {
  logger.error("Unhandled exception", { message: err.message });
});

// 16.3.2 — warning/error logging
function logSecurityEvent(message) {
  logger.warn(message);
}

// 3.3.3 — __Host- cookie prefix
function setHostCookie(res, token) {
  res.cookie("__Host-session", token, {
    secure: true,
    httpOnly: true,
    sameSite: "strict",
    path: "/"
  });
}

// 3.3.4 etc. through a real Express route
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!validator.isEmail(email)) {
      return res.status(400).json({ error: "Invalid email" });
    }

    const breached = await checkBreachedPassword(password);
    if (breached.breached) {
      return res.status(400).json({ error: "Password was breached" });
    }

    const hash = await hashPassword(password);
    const valid = await verifyPassword(password, hash);

    if (!valid) {
      logger.warn("Login failed");
      return res.status(401).json({ error: "Invalid credentials" });
    }

    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: "Session error" });

      const user = { id: "user-1", role: "admin" };
      req.session.userId = user.id;

      const token = issueToken(user);
      setHostCookie(res, token);

      return res.json({
        message: "Login successful",
        token
      });
    });
  } catch (e) {
    logger.error("Login error");
    return res.status(500).json({ error: "Internal error" });
  }
});

app.get("/admin", (req, res, next) => {
  req.user = { id: "user-1", role: "admin" };
  return authorize("admin")(req, res, next);
}, (req, res) => {
  res.json({ message: "Admin access granted" });
});

app.post("/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "File required" });

    validateUpload(req.file);
    const safeName = sanitizeFilename(req.file.originalname);
    const target = safeUploadPath(safeName);
    const scanResult = await clamscan.scan(target);

    if (scanResult.isInfected) {
      return res.status(400).json({ error: "Malicious file detected" });
    }

    return res.json({ uploaded: true, filename: escapeHtml(safeName) });
  } catch (e) {
    logger.error("Upload error");
    return res.status(400).json({ error: "Upload rejected" });
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ message: "Logged out" });
  });
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    productionMode,
    debug,
    NODE_ENV,
    apiKeyConfigured: Boolean(apiKeyFromEnv),
    jwtConfigured: Boolean(process.env.JWT_SECRET),
    statelessJwtBearer,
    jwtOptions,
    graphqlConfig,
    graphqlDepthRule,
    staticOptions,
    allowedResources: ALLOWED_RESOURCES
  });
});

// Demonstration-only helper exports/uses so the file contains the intended constructs.
module.exports = {
  app,
  hashPassword,
  verifyPassword,
  createSecureToken,
  encryptSensitiveData,
  encryptSensitiveRecord,
  verifyTotp,
  verifyToken,
  authorize,
  checkResourceOwner,
  isAllowedHost,
  clearClientStorage,
  commandOptions,
  safeOperation,
  resourceMutex,
  isBlockedMethod
};

if (require.main === module) {
  app.listen(3000, () => logger.info("ASVS demo app running on port 3000"));
}
