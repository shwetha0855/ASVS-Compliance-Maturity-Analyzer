const assert = require("assert");
const {
  createSecureToken,
  verifyTotp,
  isAllowedHost,
  commandOptions,
  isBlockedMethod
} = require("./server");

assert.strictEqual(createSecureToken().length, 64);
assert.strictEqual(isAllowedHost("api.example.com"), true);
assert.strictEqual(isAllowedHost("evil.example"), false);
assert.strictEqual(commandOptions().shell, false);
assert.strictEqual(isBlockedMethod("TRACE"), true);
assert.strictEqual(isBlockedMethod("GET"), false);

console.log("ASVS demo smoke tests passed.");
