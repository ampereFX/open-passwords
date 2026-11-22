// The MAIN-world guard swallows conditional passkey autofill when the toggle is on.
// It must not let a request through before it knows the setting, and must hand held
// requests back to the browser when the toggle turns off. Run: npm test

import { readFileSync } from "node:fs";
import vm from "node:vm";

let failed = 0;
let passed = 0;
function check(name, cond, detail) {
  if (cond) return void (passed += 1);
  failed += 1;
  console.error(`FAIL  ${name}${detail === undefined ? "" : `\n      ${JSON.stringify(detail)}`}`);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const src = readFileSync(new URL("../src/passkey-guard.js", import.meta.url), "utf8");

function page() {
  const calls = [];
  const target = new EventTarget();
  const ctx = {
    navigator: { credentials: { get: (o) => (calls.push(o), Promise.resolve("browser-ui")) } },
    addEventListener: target.addEventListener.bind(target),
    dispatch: (name) => target.dispatchEvent(new Event(name)),
    setTimeout,
    DOMException,
    Promise,
    Set,
  };
  vm.runInNewContext(src, ctx);
  return { ctx, calls, get: (o) => ctx.navigator.credentials.get(o) };
}
const cond = () => ({ mediation: "conditional", publicKey: {} });

// a request before the setting is known is held, then released when it is off
{
  const p = page();
  const r = p.get(cond());
  await sleep(5);
  check("early request held", p.calls.length === 0);
  p.ctx.dispatch("openpasswords:hide-passkeys-off");
  check("released when off", (await r) === "browser-ui" && p.calls.length === 1);
}

// on: conditional requests stay pending, modal ones pass
{
  const p = page();
  p.ctx.dispatch("openpasswords:hide-passkeys-on");
  let settled = false;
  p.get(cond()).then(() => (settled = true));
  const modal = await p.get({ publicKey: {} });
  await sleep(5);
  check("on: conditional swallowed", !settled && p.calls.length === 1);
  check("on: modal passes", modal === "browser-ui");
  p.ctx.dispatch("openpasswords:hide-passkeys-off");
  await sleep(5);
  check("turning off releases held requests", settled && p.calls.length === 2);
}

// abort while held rejects and is never released later
{
  const p = page();
  p.ctx.dispatch("openpasswords:hide-passkeys-on");
  const ac = new AbortController();
  const r = p.get({ ...cond(), signal: ac.signal }).then(() => "resolved", (e) => e.name);
  ac.abort();
  check("abort rejects", (await r) === "AbortError");
  p.ctx.dispatch("openpasswords:hide-passkeys-off");
  await sleep(5);
  check("aborted request not released", p.calls.length === 0);
}

// no answer from the bridge: fall back to letting requests through
{
  const p = page();
  const r = p.get(cond());
  check("bridge silent: released after fallback", (await r) === "browser-ui");
}

console.log(`passkey self-test: ${passed} passed, ${failed} failed`);
if (failed) process.exit(1);
