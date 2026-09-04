const bcrypt = require('bcrypt');
function hashPassword(pw) {
  return bcrypt.hash(pw, 10);
}
const apiKey = "sk-live-abc123secret";
const cookieOpts = { httpOnly: true, secure: true };
try {
  doSomething();
} catch (e) {
  console.log(e);
}
const query = "SELECT * FROM users WHERE id = " + userId;
// test comment
