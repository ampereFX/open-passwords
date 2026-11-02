// Proves the diagnostics layer cannot store a secret.
//
// Run: node scripts/log-selftest.mjs   (or: npm test)
//
// The whole point of src/log.js is that one careless call site must not be able to
// write a vault password, a pairing code or a TOTP into an export the user emails
// to a maintainer. These assertions are the contract.

import { DiagLog, errInfo, maskUser, redactText, safeUrl, sanitize, serialize } from "../src/log.js";

let failed = 0;
let passed = 0;

function check(name, cond, detail) {
  if (cond) {
    passed += 1;
    return;
  }
  failed += 1;
  console.error(`FAIL  ${name}${detail === undefined ? "" : `\n      ${JSON.stringify(detail)}`}`);
}

function eq(name, got, want) {
  check(name, JSON.stringify(got) === JSON.stringify(want), { got, want });
}

// --- key denylist -------------------------------------------------------------
eq("password is redacted", sanitize({ password: "hunter2" }), { password: "[redacted]" });
eq("pwd is redacted", sanitize({ pwd: "hunter2" }), { pwd: "[redacted]" });
eq("pin is redacted", sanitize({ pin: "482913" }), { pin: "[redacted]" });
eq("code is redacted", sanitize({ code: "482913" }), { code: "[redacted]" });
eq("otp is redacted", sanitize({ otp: "482913" }), { otp: "[redacted]" });
eq("SDATA is redacted", sanitize({ SDATA: "AABBCC" }), { SDATA: "[redacted]" });
eq("sharedKey is redacted", sanitize({ sharedKey: "ff00" }), { sharedKey: "[redacted]" });
eq("nested secret is redacted", sanitize({ a: { b: { password: "x" } } }), {
  a: { b: { password: "[redacted]" } },
});
eq("camelCase secret is redacted", sanitize({ userPassword: "x" }), { userPassword: "[redacted]" });
eq("apiToken is redacted", sanitize({ apiToken: "x" }), { apiToken: "[redacted]" });
eq("credentials array is redacted", sanitize({ credentials: [{ password: "x" }] }), {
  credentials: "[redacted]",
});

// --- legitimate fields survive ------------------------------------------------
eq(
  "diagnostic fields are untouched",
  sanitize({ host: "bank.example", n: 2, ok: true, why: "no_login_context", pwLen: 12 }),
  { host: "bank.example", n: 2, ok: true, why: "no_login_context", pwLen: 12 },
);
eq("undefined fields are dropped", sanitize({ a: undefined, b: 1 }), { b: 1 });
eq("nested errInfo keeps errCode", sanitize({ err: errInfo({ name: "Error", message: "boom", code: "challenge_reissued" }) }).err.errCode, "challenge_reissued");

// --- value-level redaction ----------------------------------------------------
check("otpauth uri is redacted", redactText("otpauth://totp/ACME?secret=JBSWY3DPEHPK3PXP") === "[otpauth]");
check("six digit run is redacted", redactText("your code 482913 expires").includes("[6d]"));
check("six digit run is redacted (msg)", !redactText("code 482913").includes("482913"));
check("long base64 is redacted", redactText("A".repeat(60)).includes("[b64]"));
check("long hex is redacted", /\[(b64|hex)\]/.test(redactText("ab".repeat(30))), redactText("ab".repeat(30)));
check("long text is truncated", redactText("x".repeat(500)).length < 320);
check("nine digit number is not a code", redactText("id 123456789").includes("123456789"));

// --- identifiers --------------------------------------------------------------
const masked = maskUser("john.doe@example.com");
check("masked user hides the local part", !masked.includes("ohn.doe"), masked);
check("masked user keeps the domain", masked.endsWith("@example.com"), masked);
eq("masked user handles empty", maskUser(""), "");
eq("safeUrl drops query and hash", safeUrl("https://bank.example/login?token=secret#frag"), "bank.example/login");
eq("safeUrl rejects non-http", safeUrl("chrome://extensions"), "chrome://");

// --- error objects ------------------------------------------------------------
const info = errInfo(new Error("timeout waiting for response"));
eq("errInfo name", info.name, "Error");
check("errInfo has no raw stack object", typeof info.frames === "object" && Array.isArray(info.frames));
check("errInfo on a string", errInfo("boom").msg === "boom");
check("errInfo on null does not throw", errInfo(null).name === "unknown");

// --- circular / hostile input -------------------------------------------------
const circular = { host: "a.example" };
circular.self = circular;
check("circular input does not throw", typeof sanitize(circular) === "object");

// --- the buffer ---------------------------------------------------------------
const log = new DiagLog({ maxEvents: 3 });
log.push({ t: "fill", lvl: "info", d: { password: "hunter2", pwLen: 7, pin: "482913" } });
log.push({ t: "fill", lvl: "warn", d: { err: new Error("nope"), code: "482913" } });
const exportText = serialize(log.snapshot());
check("export does not contain the password", !exportText.includes("hunter2"), exportText.slice(0, 200));
check("export does not contain the pin", !exportText.includes("482913"), exportText.slice(0, 200));
check("export keeps the useful length", exportText.includes('"pwLen": 7'));
check("export is valid json", (() => {
  try {
    JSON.parse(exportText);
    return true;
  } catch {
    return false;
  }
})());

for (let i = 0; i < 10; i += 1) log.push({ t: "noise", lvl: "debug", d: { i } });
check("ring buffer keeps maxEvents", log.snapshot().events.length === 3, log.snapshot().events.length);
check("ring buffer keeps the newest", log.snapshot().events.at(-1).d.i === 9);
check("warn/error survives trimming", log.snapshot().errors.length >= 1);

// --- summary ------------------------------------------------------------------
if (failed) {
  console.error(`\n${failed} failed, ${passed} passed`);
  process.exit(1);
}
console.log(`log-selftest: ${passed} passed`);
