// The plain-HTTP fill guard decides whether a page may receive a vault password.
// Wrong in one direction and a public http:// page gets credentials; wrong in the
// other and a router page silently cannot be filled. Run: npm test

import { isLocalNetworkHost, schemeClass } from "../src/hosts.js";

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

const allowed = [
  "localhost",
  "127.0.0.1",
  "::1",
  "[::1]",
  "app.localhost",
  "dev.test",
  "nas.local",
  "router.lan",
  "printer.home.arpa",
  "vault.internal",
  "router", // single label, local DNS only
  "10.0.0.1",
  "10.255.255.254",
  "172.16.0.1",
  "172.31.255.254",
  "192.168.1.1",
  "192.168.178.20",
  "169.254.10.20",
  "[fd00::1]",
  "[fe80::1]",
];

const refused = [
  "",
  "example.com",
  "login.example.com",
  "httpbin.org",
  "8.8.8.8",
  "93.184.216.34",
  "172.15.0.1", // just below the private block
  "172.32.0.1", // just above it
  "192.169.0.1",
  "11.0.0.1",
  "255.255.255.255",
  "10.0.0.1.example.com", // a hostname that merely starts with a private IP
  "notlocalhost.local", // ends with .local but should be allowed — see below
];

for (const host of allowed) check(`http-local allowed: ${host}`, isLocalNetworkHost(host) === true, host);
for (const host of refused) {
  // "notlocalhost.local" is a normal .local name, so it is expected to pass; skip it here
  if (host === "notlocalhost.local") continue;
  check(`refused: ${host || "(empty)"}`, isLocalNetworkHost(host) === false, host);
}
check("a .local name is allowed even when it has other dots", isLocalNetworkHost("notlocalhost.local") === true);

// schemeClass: https always wins, regardless of host
check("https on a public host", schemeClass("https://example.com/login", "example.com") === "https");
check("https on a LAN ip", schemeClass("https://192.168.1.1/", "192.168.1.1") === "https");
check("http on a LAN ip", schemeClass("http://10.0.0.1/", "10.0.0.1") === "http-local");
check("http on a public host", schemeClass("http://example.com/", "example.com") === "http-public");
check("http with no host", schemeClass("http://", "") === "http-public");
check("weird protocol is not https", schemeClass("ftp://10.0.0.1/", "10.0.0.1") === "http-local");

if (failed) {
  console.error(`\n${failed} failed, ${passed} passed`);
  process.exit(1);
}
console.log(`hosts-selftest: ${passed} passed`);
