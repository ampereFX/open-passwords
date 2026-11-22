// Native requests are serialized behind one lock and replies carry no correlation id.
// A reply that never comes must not stall every later request, and a reply that may
// belong to an abandoned request must never be handed out as a password. Run: npm test

import { ApplePasswords, Command } from "../src/protocol.js";

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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const settle = (p) => p.then((v) => ({ ok: true, v }), (e) => ({ ok: false, e }));

function client() {
  const events = [];
  const c = new ApplePasswords({ log: (e) => events.push(e) });
  const sent = [];
  c.port = { postMessage: (m) => sent.push(m), disconnect() {} };
  return { c, events, sent };
}

const PW = Command.GET_PASSWORD_FOR_LOGIN_NAME;
const NAMES = Command.GET_LOGIN_NAMES_FOR_URL;

// a lookup queued behind a hung request reports busy instead of hanging, and never runs late
{
  const { c } = client();
  c._withLock(() => new Promise(() => {}));
  let ran = false;
  const r = await settle(c._withLock(async () => (ran = true), 30));
  check("busy: rejects", !r.ok && r.e.code === "busy", r.e?.message);
  await sleep(10);
  check("busy: skipped fn did not run", !ran);
}

// a lookup that gets its turn in time is not cut off by the wait bound
{
  const { c } = client();
  const r = await settle(c._withLock(async () => { await sleep(60); return 7; }, 20));
  check("wait bound only covers queueing", r.ok && r.v === 7, r.e?.message);
}

// refresh frees the lock held by a request the helper never answered
{
  const { c, events } = client();
  const hung = settle(c._withLock(() => c._send(PW, {}, null)));
  await sleep(5);
  const next = settle(c._withLock(async () => "next"));
  const n = c.abortStale(0, "test");
  check("abort: one request aborted", n === 1, n);
  check("abort: hung request rejects", !(await hung).ok);
  const r = await next;
  check("abort: queued request runs", r.ok && r.v === "next", r.e?.message);
  check("abort: logged", events.some((e) => e.t === "native.abort"));
}

// abortStale leaves young requests alone
{
  const { c } = client();
  const p = settle(c._send(NAMES, {}, null));
  check("abort: young request kept", c.abortStale(60_000, "test") === 0);
  c._dispatch({ cmd: NAMES });
  check("abort: young request still answered", (await p).ok);
}

// after an abandoned password request, the next reply is refused, the one after is fine
{
  const { c, events } = client();
  const first = settle(c._send(PW, {}, null));
  c.abortStale(0, "test");
  await first;
  const second = settle(c._send(PW, {}, null));
  c._dispatch({ cmd: PW, marker: "late reply for the abandoned request" });
  const r2 = await second;
  check("stale: secret reply refused", !r2.ok && r2.e.code === "stale_reply", r2.v);
  check("stale: logged", events.some((e) => e.t === "native.stale-reply"));
  const third = settle(c._send(PW, {}, null));
  c._dispatch({ cmd: PW, marker: "fresh" });
  const r3 = await third;
  check("stale: next reply accepted", r3.ok && r3.v.marker === "fresh", r3.e?.message);
}

// a timed-out password request also poisons exactly one following reply
{
  const { c } = client();
  const t = await settle(c._send(PW, {}, 10));
  check("timeout: rejects", !t.ok && /timeout/.test(t.e.message));
  const p = settle(c._send(PW, {}, null));
  c._dispatch({ cmd: PW });
  check("timeout: following secret reply refused", !(await p).ok);
}

// non-secret replies after an abandoned request are passed through
{
  const { c } = client();
  await settle(c._send(NAMES, {}, 10));
  const p = settle(c._send(NAMES, {}, null));
  c._dispatch({ cmd: NAMES });
  check("non-secret: reply passed through", (await p).ok);
}

// a late reply with nobody waiting clears the abandoned mark
{
  const { c } = client();
  await settle(c._send(PW, {}, 10));
  c._dispatch({ cmd: PW });
  const p = settle(c._send(PW, {}, null));
  c._dispatch({ cmd: PW, marker: "fresh" });
  const r = await p;
  check("late reply consumed the mark", r.ok && r.v.marker === "fresh", r.e?.message);
}

// a closed port settles every waiter so the lock frees up
{
  const { c } = client();
  const hung = settle(c._withLock(() => c._send(PW, {}, null)));
  await sleep(5);
  const next = settle(c._withLock(async () => "next"));
  c.disconnect();
  check("disconnect: waiter rejects", !(await hung).ok);
  const r = await next;
  check("disconnect: queued request runs", r.ok && r.v === "next", r.e?.message);
}

console.log(`protocol self-test: ${passed} passed, ${failed} failed`);
if (failed) process.exit(1);
