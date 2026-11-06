// alarm keep-alive holds the MV3 worker so the PIN isnt re-prompted every idle-out

import { ApplePasswords, State } from "./protocol.js";
import { schemeClass } from "./hosts.js";
import { DiagLog, errInfo, maskUser, safeUrl, sanitize } from "./log.js";

const VERSION = chrome.runtime.getManifest().version;
/** true when this worker is the incognito instance (split mode), which explains most "works in one window" reports */
const INCOGNITO = (() => {
  try {
    return chrome.extension?.inIncognitoContext === true;
  } catch (_) {
    return false;
  }
})();

const diag = new DiagLog();

// verbose is the default: a rare bug is worth more than a small buffer. Turning it off
// keeps warnings/errors and drops the per-focus, per-native-call detail.
let verboseDiag = true;
try {
  chrome.storage.local.get({ verboseDiagnostics: true }, (d) => {
    verboseDiag = d?.verboseDiagnostics !== false;
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.verboseDiagnostics) verboseDiag = changes.verboseDiagnostics.newValue !== false;
  });
} catch (_) {}

function logUp(t, lvl, d, extra = {}) {
  if (!verboseDiag && lvl === "debug") return;
  try {
    diag.push({ t, lvl, d, ...extra });
  } catch (_) {}
}

const client = new ApplePasswords({
  log: ({ t, lvl, d }) => {
    const { trace, ...rest } = d || {};
    diag.push({ t, lvl, d: rest, trace });
  },
});

client.onStateChange((s) => {
  if (s !== State.Unlocked) {
    pwCacheClear();
    otpByTab.clear();
  }
  logUp("state.broadcast", "info", {
    state: s,
    reason: client.stateReason,
    incognito: INCOGNITO,
    cachedPw: pwCacheSize(),
    pendingSaves: pendingSaves.length,
    lastFillTabs: lastFillByTab.size,
  });
  broadcast({ type: "state", state: s });
});

// one attempt per challenge, never a retry loop, a wrong read burns the code. only when the
// user asks for a code (popup, unlock click), never at browser launch
const AUTOPAIR_HOST = "com.openpasswords.autopair";
let autoPairBusy = false;
let autoPairError = null;

function autoPairEnabled() {
  return new Promise((r) => chrome.storage.local.get({ autoPair: false }, (o) => r(!!o.autoPair)));
}

function autoPairMsg(body) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendNativeMessage(AUTOPAIR_HOST, body, (r) => {
        const err = chrome.runtime.lastError;
        resolve(err ? { ok: false, error: err.message } : r || { ok: false, error: "no reply" });
      });
    } catch (e) {
      resolve({ ok: false, error: String(e?.message ?? e) });
    }
  });
}

async function tryAutoPair(reason) {
  if (autoPairBusy || client.state !== State.NeedsPin) return false;
  if (!(await autoPairEnabled())) return false;
  autoPairBusy = true;
  logUp("autopair.start", "info", { reason, hasChallenge: client.hasChallenge });
  try {
    // reuse a code already on screen rather than replacing it under the user
    await withTimeout(client.requestChallenge({ ifNeeded: true }), 8000, "challenge timed out");
    const res = await autoPairMsg({ action: "read", timeoutMs: 6000 });
    if (!res.ok || !res.code) {
      autoPairError = res.error || "no code visible";
      logUp("autopair.skipped", "warn", { reason, error: autoPairError, codeLen: 0 });
      return false;
    }
    logUp("autopair.code", "debug", { codeLen: String(res.code).length });
    await withTimeout(client.verifyPin(res.code), 8000, "verification timed out");
    autoPairError = null;
    logUp("autopair.ok", "info", { reason });
    if (client.ready) {
      flushPendingSaves();
      // only the active tab can have the inline PIN box open
      try {
        const tab = await activeTab();
        if (tab?.id != null) chrome.tabs.sendMessage(tab.id, { type: "unlocked" }).catch(() => {});
      } catch (_) {}
    }
    return client.ready;
  } catch (e) {
    autoPairError = String(e?.message ?? e);
    logUp("autopair.failed", "warn", { reason, err: errInfo(e) });
    return false;
  } finally {
    autoPairBusy = false;
  }
}

client.onOneTimeCodeAvailable(async () => {
  try {
    const tab = await activeTab();
    logUp("otp.available", "info", { tab: tab?.id, host: tab?.url ? safeUrl(tab.url) : undefined });
    if (tab?.id == null) return;
    otpByTab.delete(tab.id);
    chrome.tabs.sendMessage(tab.id, { type: "oneTimeCodeAvailable" }).catch(() => {});
  } catch (e) {
    logUp("otp.available.failed", "warn", { err: errInfo(e) });
  }
});

// rows resolve by id so the page never chooses the username/domain
const otpByTab = new Map();
const OTP_LIST_TTL_MS = 120_000;

// apple walks the whole parent chain via webNavigation, the top URL covers a same-site iframe without another permission
function frameUrlsFor(sender) {
  const urls = [];
  for (const u of [sender.url, sender.tab?.url]) {
    if (u && /^https?:/i.test(u) && !urls.includes(u)) urls.push(u);
  }
  return urls;
}

// never the code itself at list time
function otpRow(e, i) {
  return { id: i, source: e.source, username: e.username, domain: e.domain };
}

async function listOneTimeCodes(tabId, frameId, frameUrls) {
  const { entries, requiresAuth } = await client.getOneTimeCodes(tabId, frameId, frameUrls);
  otpByTab.set(tabId, { at: Date.now(), entries, frameId, frameUrls });
  logUp("otp.list", "debug", {
    tab: tabId,
    frame: frameId,
    n: entries.length,
    requiresAuth,
    sources: [...new Set(entries.map((e) => e.source))],
    frames: (frameUrls || []).map((u) => safeUrl(u)),
  });
  return { rows: entries.map(otpRow), requiresAuth };
}

// TOTP is re-read now, the value rotates and this read triggers Touch ID when the vault demands it
async function resolveOneTimeCode(tabId, id) {
  const cached = otpByTab.get(tabId);
  const age = cached ? Date.now() - cached.at : -1;
  if (!cached || age > OTP_LIST_TTL_MS) {
    logUp("otp.resolve.failed", "warn", { tab: tabId, id, why: cached ? "list expired" : "no list", age });
    throw new Error("code list expired, focus the field again");
  }
  const entry = cached.entries[id];
  if (!entry) {
    logUp("otp.resolve.failed", "warn", { tab: tabId, id, why: "unknown id", listed: cached.entries.length });
    throw new Error("unknown code");
  }
  if (entry.source !== "totp") {
    logUp("otp.resolve", "debug", { tab: tabId, id, source: entry.source, codeLen: String(entry.code || "").length, age });
    return entry.code;
  }
  const fresh = await client.readOneTimeCode(tabId, cached.frameId, cached.frameUrls, entry.username);
  const match =
    fresh.find((e) => e.source === "totp" && e.username === entry.username && e.domain === entry.domain) ||
    fresh.find((e) => e.source === "totp");
  if (!match?.code) {
    logUp("otp.resolve.failed", "warn", { tab: tabId, id, why: "no totp in fresh read", n: fresh.length });
    throw new Error("no code returned");
  }
  logUp("otp.resolve", "debug", {
    tab: tabId,
    id,
    source: "totp",
    exactMatch: !!(match.username === entry.username && match.domain === entry.domain),
    codeLen: String(match.code).length,
  });
  return match.code;
}

function broadcast(msg) {
  chrome.runtime.sendMessage(msg).catch((e) => {
    // "no receiving end" is normal when no popup is open, anything else is not
    const text = String(e?.message ?? e);
    if (!/Receiving end does not exist|Could not establish connection/i.test(text)) {
      logUp("broadcast.failed", "debug", { err: text });
    }
  });
}

const mruByHost = new Map();
function recordMru(host, username) {
  if (!host || !username) return;
  const u = username.toLowerCase();
  const arr = (mruByHost.get(host) || []).filter((x) => x !== u);
  arr.unshift(u);
  mruByHost.set(host, arr.slice(0, 10));
}
function orderByMru(host, logins) {
  const order = mruByHost.get(host);
  if (!order || !order.length) return logins;
  const rank = (u) => {
    const i = order.indexOf((u || "").toLowerCase());
    return i === -1 ? Infinity : i;
  };
  return [...logins].sort((a, b) => rank(a.username) - rank(b.username));
}

// "" lets the native sheet ask, null saves nothing
function pickSaveTarget({ host, existing, detected, generated, newPwCtx }) {
  const matched = detected && existing.find((u) => u.toLowerCase() === detected.toLowerCase());
  // update only on a new password, stay quiet on a plain re-login
  if (matched) return generated || newPwCtx ? matched : null;
  if (detected) return detected;
  // attach to the MRU account, apple's sheet lets the user re-pick
  if (newPwCtx && existing.length) {
    return orderByMru(host, existing.map((u) => ({ username: u })))[0].username;
  }
  if (generated) return "";
  return null;
}

// a reset can navigate away, so stash saves that arrived while locked and flush on unlock
const pendingSaves = [];
function queuePendingSave(save) {
  const k = `${save.host} ${(save.detected || "").toLowerCase()}`;
  const i = pendingSaves.findIndex((p) => `${p.host} ${(p.detected || "").toLowerCase()}` === k);
  if (i >= 0) pendingSaves.splice(i, 1);
  pendingSaves.push(save);
  while (pendingSaves.length > 10) pendingSaves.shift();
}
async function flushPendingSaves() {
  if (!client.ready || !pendingSaves.length) return;
  const batch = pendingSaves.splice(0);
  for (const s of batch) {
    try {
      let existing = [];
      try {
        existing = (await client.getLoginNamesForURL(s.tabId, s.frameUrl))
          .map((l) => l.username)
          .filter(Boolean);
      } catch {}
      const target = pickSaveTarget({ ...s, existing });
      if (target === null) continue;
      await client.saveLogin(s.tabId, s.frameUrl, target, s.password);
    } catch {}
  }
}

// keeps internal spaces so distinct usernames arent merged
function normUsername(u) {
  return (u || "")
    .normalize("NFC")
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .trim()
    .toLowerCase();
}

// helper returns the same username for www + apex entries, fills look up by username so dupes are useless
function uniqueByUsername(logins) {
  const seen = new Set();
  return logins.filter((l) => {
    const k = normUsername(l.username);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

const lastFillByTab = new Map();

// re-filling the same login skips a second Touch ID, apple prompts every read
const PW_CACHE_TTL_MS = 120_000;
const pwCache = new Map();
function pwCacheKey(host, username) {
  return `${host}\n${(username || "").toLowerCase()}`;
}
function pwCacheGet(host, username) {
  const k = pwCacheKey(host, username);
  const hit = pwCache.get(k);
  if (!hit) return null;
  if (Date.now() - hit.at > PW_CACHE_TTL_MS) {
    pwCache.delete(k);
    return null;
  }
  return hit.cred;
}
function pwCacheSet(host, cred) {
  if (!host || !cred?.username) return;
  pwCache.set(pwCacheKey(host, cred.username), { cred, at: Date.now() });
}
function pwCacheClear() {
  pwCache.clear();
}
function pwCacheSize() {
  return pwCache.size;
}

function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(label || "timed out")), ms)),
  ]);
}

// defeat the MV3 ~30s idle shutdown that kills the session
const KEEPALIVE_ALARM = "open-passwords-keepalive";
chrome.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: 0.4 });
chrome.alarms.onAlarm.addListener((a) => {
  if (a.name !== KEEPALIVE_ALARM) return;
  // touching an extension API resets the idle timer
  chrome.runtime.getPlatformInfo(() => void chrome.runtime.lastError);
});

async function ensureConnected() {
  if (client.state === State.Disconnected) {
    logUp("connect.ensure", "debug", { state: client.state });
    try {
      await client.connect();
    } catch (e) {
      // surfaced via state change (NoHelper / Disconnected)
      logUp("connect.ensure.failed", "warn", { err: errInfo(e), state: client.state, portOpen: client.port !== undefined });
    }
  } else if (client.state !== State.Unlocked) {
    // NoHelper / NeedsPin: a retry would early-return on the open port, worth recording
    logUp("connect.ensure.skip", "debug", { state: client.state, portOpen: client.port !== undefined });
  }
}

diag
  .load({ ver: VERSION, incognito: INCOGNITO, ua: navigator.userAgent, scope: "service worker" })
  .then(() => logUp("sw.boot", "info", { ver: VERSION, incognito: INCOGNITO, state: client.state, alarms: !!chrome.alarms }))
  .catch(() => {});

self.addEventListener("error", (e) => {
  logUp("sw.error", "error", { err: errInfo(e?.error || e?.message || "unknown") });
});
self.addEventListener("unhandledrejection", (e) => {
  logUp("sw.unhandled-rejection", "error", { err: errInfo(e?.reason) });
});

chrome.runtime.onStartup.addListener(() => {
  logUp("sw.event", "info", { name: "onStartup" });
  ensureConnected();
});
chrome.runtime.onInstalled.addListener((d) => {
  logUp("sw.event", "info", { name: "onInstalled", reason: d?.reason, previous: d?.previousVersion });
  ensureConnected();
});
ensureConnected();

function suppressChromeAutofill() {
  const svc = chrome.privacy?.services;
  if (!svc?.passwordSavingEnabled) return;
  // credit-card autofill is never touched, google pay keeps working
  chrome.storage?.local?.get({ suppressSaveBubble: true, suppressAddressAutofill: false }, (o) => {
    if (chrome.runtime.lastError) return;
    logUp("pref.apply", "debug", {
      suppressSaveBubble: !!o.suppressSaveBubble,
      suppressAddressAutofill: !!o.suppressAddressAutofill,
    });
    try {
      if (o.suppressSaveBubble) {
        svc.passwordSavingEnabled.set({ value: false }, () => {
          const err = chrome.runtime.lastError?.message;
          logUp("pref.set", err ? "warn" : "debug", { which: "passwordSavingEnabled", value: false, err });
        });
      }
      if (o.suppressAddressAutofill && svc.autofillAddressEnabled) {
        svc.autofillAddressEnabled.set({ value: false }, () => {
          const err = chrome.runtime.lastError?.message;
          logUp("pref.set", err ? "warn" : "debug", { which: "autofillAddressEnabled", value: false, err });
        });
      }
    } catch (e) {
      logUp("pref.set.failed", "warn", { err: errInfo(e) });
    }
  });
}
chrome.runtime.onInstalled.addListener(suppressChromeAutofill);
chrome.runtime.onStartup.addListener(suppressChromeAutofill);
suppressChromeAutofill();

// content messages carry sender.tab, the popup never does
function isFromOwnUi(sender) {
  return sender.id === chrome.runtime.id && sender.tab === undefined;
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function registrableHost(u) {
  try {
    return new URL(u).hostname.toLowerCase();
  } catch {
    return null;
  }
}

// Where plain HTTP is the norm rather than a red flag: loopback, RFC 6761 reserved
// TLDs, the private/link-local address ranges and single-label LAN names. Router and
// NAS admin pages live there and only speak http://, and a fill there still needs an
// explicit click. A public http:// origin is never fillable: that is the case the
// guard exists for. The matrix itself lives in hosts.js so it can be tested.
// only these from a content script, none returns a password to the page
const CONTENT_ALLOWED = new Set([
  "inlineLogins",
  "inlineFill",
  "inlineOneTimeCodes",
  "inlineFillOneTimeCode",
  "requestChallenge",
  "verifyPin",
  "resolveSave",
  "log",
]);

chrome.commands?.onCommand.addListener(async (command) => {
  logUp("shortcut", "info", { command });
  if (command !== "fill-login") return;
  const tab = await activeTab();
  if (tab?.id == null) return;
  chrome.tabs.sendMessage(tab.id, { type: "shortcut" }).catch(() => {});
});

// what the UI/popup is allowed to see about a response, without ever echoing a secret
function summarizeResponse(res) {
  if (res === undefined) return "(no response)";
  if (res === null || typeof res !== "object") return sanitize(res);
  const out = {};
  for (const [k, v] of Object.entries(res)) {
    if ((k === "logins" || k === "rows" || k === "entries") && Array.isArray(v)) {
      out[k] = v.length;
      const first = v.find((x) => x && typeof x === "object" && x.username);
      if (first) out.firstUser = maskUser(first.username);
    } else if (k === "code") {
      out.code = v ? `[redacted len=${String(v).length}]` : v;
    } else {
      out[k] = v;
    }
  }
  return sanitize(out);
}

// the one place where every message and every response is recorded
chrome.runtime.onMessage.addListener((msg, sender, rawRespond) => {
  const started = Date.now();
  const fromUi = isFromOwnUi(sender);
  const fromContent = sender.id === chrome.runtime.id && sender.tab !== undefined;
  const trace = msg?.trace ? String(msg.trace).slice(0, 40) : undefined;
  const ctx = {
    tab: sender.tab?.id,
    frame: sender.frameId,
    top: sender.frameId === 0,
    inc: sender.tab?.incognito === true ? true : undefined,
    host: sender.url ? safeUrl(sender.url) : undefined,
    route: fromUi ? "ui" : fromContent ? "content" : "other",
  };
  if (trace) client.trace = trace;
  const isLog = msg?.type === "log";
  if (!isLog) {
    logUp(
      "msg.in",
      "debug",
      { type: msg?.type, keys: msg && typeof msg === "object" ? Object.keys(msg) : [], state: client.state },
      { trace, ctx },
    );
  }
  // every response goes through here: nothing answers without leaving a trace
  const sendResponse = (res) => {
    if (!isLog) {
      logUp(
        "msg.out",
        res?.ok === false ? "warn" : "debug",
        {
          type: msg?.type,
          dur: Date.now() - started,
          res: summarizeResponse(res),
          state: client.state,
          stateReason: client.stateReason,
        },
        { trace, ctx },
      );
    }
    try {
      rawRespond(res);
    } catch (_) {}
  };
  (async () => {
    try {
      if (!fromUi && !(fromContent && CONTENT_ALLOWED.has(msg?.type))) {
        logUp("msg.forbidden", "warn", { type: msg?.type, route: ctx.route }, { trace, ctx });
        sendResponse({ ok: false, error: "forbidden" });
        return;
      }

      switch (msg?.type) {
        case "log": {
          // content scripts and the popup append through here, the buffer stays in the worker
          const events = Array.isArray(msg.events) ? msg.events.slice(0, 40) : [];
          let n = 0;
          for (const ev of events) {
            if (!ev || typeof ev !== "object") continue;
            if (ev.lvl === "debug" && !verboseDiag) continue;
            diag.push({
              t: String(ev.t || "content").slice(0, 40),
              lvl: ["debug", "info", "warn", "error"].includes(ev.lvl) ? ev.lvl : "debug",
              d: ev.d,
              trace: ev.trace || trace,
              ctx: ev.ctx || ctx,
            });
            n++;
          }
          sendResponse({ ok: true, logged: n });
          break;
        }
        case "inlineLogins": {
          // keyed to sender.url not the top tab
          const frameUrl = sender.url;
          if (!frameUrl) return sendResponse({ ok: false, error: "no frame" });
          await ensureConnected();
          if (!client.ready) return sendResponse({ ok: true, locked: true, logins: [] });
          try {
            const logins = await client.getLoginNamesForURL(sender.tab?.id, frameUrl);
            const ordered = uniqueByUsername(orderByMru(registrableHost(frameUrl), logins));
            logUp(
              "fill.logins",
              "debug",
              { raw: logins.length, uniq: ordered.length, users: ordered.slice(0, 6).map((l) => maskUser(l.username)) },
              { trace, ctx },
            );
            sendResponse({ ok: true, locked: false, logins: ordered });
          } catch (e) {
            // this used to surface as "no saved passwords" with no hint that the query failed
            logUp("fill.logins.failed", "warn", { err: errInfo(e), state: client.state }, { trace, ctx });
            sendResponse({ ok: true, locked: false, logins: [] });
          }
          break;
        }

        case "inlineOneTimeCodes": {
          const frameUrl = sender.url;
          if (!frameUrl || sender.tab?.id == null) return sendResponse({ ok: false, error: "no frame" });
          await ensureConnected();
          // capabilities arrive with the hello, before the PIN, so locked still knows if codes are supported
          if (!client.ready)
            return sendResponse({ ok: true, locked: true, supported: client.canFillOneTimeCodes, rows: [] });
          if (!client.canFillOneTimeCodes) {
            logUp("otp.unsupported", "debug", { caps: client.capabilities }, { trace, ctx });
            return sendResponse({ ok: true, locked: false, supported: false, rows: [] });
          }
          try {
            const { rows, requiresAuth } = await listOneTimeCodes(sender.tab.id, sender.frameId ?? 0, frameUrlsFor(sender));
            sendResponse({ ok: true, locked: false, supported: true, rows, requiresAuth });
          } catch (e) {
            logUp("otp.list.failed", "warn", { err: errInfo(e) }, { trace, ctx });
            sendResponse({ ok: true, locked: false, supported: true, rows: [], error: String(e?.message ?? e) });
          }
          break;
        }

        case "inlineFillOneTimeCode": {
          const frameUrl = sender.url;
          const frameId = sender.frameId;
          if (!frameUrl || sender.tab?.id == null || frameId == null) return sendResponse({ ok: false, error: "no frame" });
          const host = registrableHost(frameUrl);
          if (schemeClass(frameUrl, host) === "http-public") {
            logUp("otp.refused", "warn", { host, why: "plain HTTP on a public host" }, { trace, ctx });
            return sendResponse({ ok: false, error: "refusing to fill on a non-HTTPS frame", reason: "insecure-origin" });
          }
          const code = await resolveOneTimeCode(sender.tab.id, Number(msg.id));
          logUp("otp.fill", "info", { id: msg.id, codeLen: String(code || "").length, expectedHost: host }, { trace, ctx });
          const resp = await chrome.tabs.sendMessage(
            sender.tab.id,
            { type: "fillOtp", code, expectedHost: host },
            { frameId },
          );
          logUp("otp.fill.result", resp?.filled ? "info" : "warn", { filled: !!resp?.filled, resp: summarizeResponse(resp) }, { trace, ctx });
          sendResponse({ ok: true, filled: !!resp?.filled });
          break;
        }

        case "inlineFill": {
          // frameId scopes the fill to the requesting frame, never broadcast (confused deputy)
          const frameUrl = sender.url;
          const frameId = sender.frameId;
          if (!frameUrl || sender.tab?.id == null || frameId == null) {
            return sendResponse({ ok: false, error: "no frame" });
          }
          const host = registrableHost(frameUrl);
          const scheme = schemeClass(frameUrl, host);
          if (scheme === "http-public") {
            logUp("fill.refused", "warn", { host, scheme, why: "plain HTTP on a public host" }, { trace, ctx });
            return sendResponse({ ok: false, error: "refusing to fill on a non-HTTPS frame", reason: "insecure-origin" });
          }
          // pass only the username through, sites is caller-supplied
          const safeLogin = { username: msg.loginName?.username };
          let cred = pwCacheGet(host, safeLogin.username);
          const cacheHit = !!cred;
          if (!cred) {
            cred = await client.getPasswordForLoginName(sender.tab.id, frameUrl, safeLogin);
            if (cred) pwCacheSet(host, cred);
          }
          logUp(
            "fill.credential",
            cred ? "info" : "warn",
            {
              host,
              scheme,
              // plain HTTP on a LAN address works (routers, NAS) but is worth seeing in a report
              insecure: scheme === "http-local",
              user: maskUser(safeLogin.username),
              cacheHit,
              found: !!cred,
              cached: pwCacheSize(),
            },
            { trace, ctx },
          );
          let filled = false;
          let reply;
          if (cred) {
            const resp = await chrome.tabs.sendMessage(
              sender.tab.id,
              {
                type: "fill",
                username: cred.username,
                password: cred.password,
                expectedHost: host,
              },
              { frameId },
            );
            filled = !!resp?.filled;
            reply = resp;
            logUp(
              "fill.result",
              filled ? "info" : "warn",
              { host, scheme, user: maskUser(cred.username), filled, resp: summarizeResponse(resp) },
              { trace, ctx },
            );
            if (filled) {
              recordMru(host, cred.username);
              lastFillByTab.set(sender.tab.id, { host, username: cred.username });
            }
          }
          // a reason the content script can turn into a visible message instead of a silent no-op
          let reason;
          if (!cred) reason = "no-credential";
          else if (!filled) reason = reply?.reason || "no-field";
          sendResponse({ ok: true, filled, reason });
          break;
        }

        case "resolveSave": {
          // saving here so a submit that navigates cant kill it
          const frameUrl = sender.url;
          if (!frameUrl || sender.tab?.id == null) {
            return sendResponse({ ok: false, error: "no frame" });
          }
          const host = registrableHost(frameUrl);
          if (schemeClass(frameUrl, host) === "http-public") {
            logUp("save.refused", "warn", { host, why: "plain HTTP on a public host" }, { trace, ctx });
            return sendResponse({ ok: false, error: "refusing to save from a non-HTTPS frame", reason: "insecure-origin" });
          }
          if (!msg.password) return sendResponse({ ok: false, error: "no password" });
          const detected = (msg.username || "").trim();
          const generated = !!msg.generated;
          const newPwCtx = !!msg.newPwCtx;
          await ensureConnected();

          // locked: stash a new-password save for unlock, a plain re-login isnt worth deferring
          if (!client.ready) {
            const willQueue = generated || newPwCtx;
            logUp(
              "save.locked",
              willQueue ? "info" : "warn",
              { host, user: maskUser(detected), pwLen: String(msg.password).length, generated, newPwCtx, queued: willQueue },
              { trace, ctx },
            );
            if (willQueue) {
              queuePendingSave({
                host,
                frameUrl,
                tabId: sender.tab.id,
                detected,
                password: msg.password,
                generated,
                newPwCtx,
              });
            }
            return sendResponse({ ok: true, saved: false, locked: true });
          }

          let existing = [];
          try {
            existing = (await client.getLoginNamesForURL(sender.tab.id, frameUrl))
              .map((l) => l.username)
              .filter(Boolean);
          } catch (e) {
            // a failed lookup changes the save decision (it looks like "first login here")
            logUp("save.existing.failed", "warn", { err: errInfo(e) }, { trace, ctx });
          }
          const target = pickSaveTarget({ host, existing, detected, generated, newPwCtx });
          logUp("save.decide", "info", {
            host,
            user: maskUser(detected),
            pwLen: String(msg.password).length,
            generated,
            newPwCtx,
            existingCount: existing.length,
            existingUsers: existing.slice(0, 6).map((u) => maskUser(u)),
            target: target === null ? "(skip)" : target ? maskUser(target) : "(ask)",
          }, { trace, ctx });
          if (target === null) return sendResponse({ ok: true, saved: false, skipped: true });
          await client.saveLogin(sender.tab.id, frameUrl, target, msg.password);
          sendResponse({ ok: true, saved: true });
          break;
        }

        case "getState":
          await ensureConnected();
          logUp("state.get", "debug", { state: client.state, reason: client.stateReason, hasChallenge: client.hasChallenge, autoPairError });
          sendResponse({
            ok: true,
            state: client.state,
            stateReason: client.stateReason,
            hasChallenge: client.hasChallenge,
            caps: {
              oneTimeCodes: client.canFillOneTimeCodes,
              newPasswordSheet: client.canOpenPasswordsAppToNewPasswordSheet,
              setUpTotp: client.canSetUpTotp,
            },
            autoPairError,
          });
          break;

        case "autoPairCheck": {
          const r = await autoPairMsg({ action: "check" });
          sendResponse(r);
          break;
        }

        case "getOneTimeCodes": {
          const tab = await activeTab();
          if (!tab?.url) return sendResponse({ ok: false, error: "no active tab" });
          if (!client.ready) return sendResponse({ ok: true, rows: [] });
          if (!client.canFillOneTimeCodes) return sendResponse({ ok: true, supported: false, rows: [] });
          const { rows, requiresAuth } = await listOneTimeCodes(tab.id, 0, frameUrlsFor({ url: tab.url, tab }));
          logUp("otp.popup.list", "debug", { tab: tab.id, n: rows.length, requiresAuth });
          sendResponse({ ok: true, supported: true, rows, requiresAuth });
          break;
        }

        case "fillOneTimeCode": {
          // every frame gets it, only the one with a code field acts. value returned so the popup can show it if none did
          const tab = await activeTab();
          if (!tab?.url) return sendResponse({ ok: false, error: "no active tab" });
          const host = registrableHost(tab.url);
          if (schemeClass(tab.url, host) === "http-public") {
            logUp("otp.refused", "warn", { host, why: "plain HTTP on a public host" }, { trace, ctx });
            return sendResponse({ ok: false, error: "refusing to fill on a non-HTTPS page", reason: "insecure-origin" });
          }
          const code = await resolveOneTimeCode(tab.id, Number(msg.id));
          let filled = false;
          try {
            const frames = await new Promise((resolve) =>
              chrome.tabs.sendMessage(tab.id, { type: "fillOtp", code, expectedHost: host }, (r) => {
                const err = chrome.runtime.lastError?.message;
                if (err) logUp("otp.popup.send-error", "warn", { err, host });
                resolve(r);
              }),
            );
            filled = !!frames?.filled;
          } catch (e) {
            logUp("otp.popup.fill.failed", "warn", { err: errInfo(e), host });
          }
          logUp("otp.popup.fill", filled ? "info" : "warn", { tab: tab.id, host, filled, codeLen: String(code || "").length });
          sendResponse({ ok: true, filled, code });
          break;
        }

        case "openPasswordsApp": {
          const tab = await activeTab();
          const url = tab?.url && /^https?:/i.test(tab.url) ? tab.url : undefined;
          logUp("app.launch.request", "info", {
            mode: msg.mode,
            host: url ? safeUrl(url) : undefined,
            caps: { newPasswordSheet: client.canOpenPasswordsAppToNewPasswordSheet, setUpTotp: client.canSetUpTotp },
            uriOk: msg.mode === "totp" ? /^(apple-)?otpauth:\/\//i.test(String(msg.uri || "")) : undefined,
          }, { trace, ctx });
          await ensureConnected();
          if (msg.mode === "totp") {
            if (!msg.uri || !/^(apple-)?otpauth:\/\//i.test(msg.uri)) return sendResponse({ ok: false, error: "no otpauth URI" });
            client.launchPasswordsApp({ totpUri: msg.uri, totpPageUrl: url });
          } else if (msg.mode === "new") {
            client.launchPasswordsApp({ newPasswordUrl: url });
          } else {
            client.launchPasswordsApp({ searchUrl: url });
          }
          sendResponse({ ok: true });
          break;
        }

        case "connect":
          logUp("connect.request", "info", { state: client.state, portOpen: client.port !== undefined }, { trace, ctx });
          await ensureConnected();
          sendResponse({ ok: true, state: client.state, stateReason: client.stateReason });
          break;

        case "requestChallenge":
          // top frame or popup only, so a hostile sub-frame cant spam native prompts
          if (fromContent && sender.frameId !== 0) {
            logUp("challenge.forbidden", "warn", { why: "frameId !== 0", frame: sender.frameId }, { trace, ctx });
            return sendResponse({ ok: false, error: "forbidden" });
          }
          await ensureConnected();
          logUp("challenge.ask", "info", { ifNeeded: !!msg.ifNeeded, hasChallenge: client.hasChallenge, state: client.state }, { trace, ctx });
          await withTimeout(client.requestChallenge({ ifNeeded: !!msg.ifNeeded }), 8000, "challenge timed out");
          // not awaited, the UI shows its PIN box while auto-pair reads the code
          tryAutoPair("request");
          sendResponse({ ok: true, state: client.state, hasChallenge: client.hasChallenge });
          break;

        case "verifyPin": {
          if (fromContent && sender.frameId !== 0) {
            logUp("verify.forbidden", "warn", { why: "frameId !== 0", frame: sender.frameId }, { trace, ctx });
            return sendResponse({ ok: false, error: "forbidden" });
          }
          await ensureConnected();
          logUp("verify.ask", "info", { pinLen: String(msg.pin || "").length, from: ctx.route, state: client.state }, { trace, ctx });
          try {
            await withTimeout(client.verifyPin(msg.pin), 8000, "verification timed out");
          } catch (e) {
            // a spent challenge cant be retried, put a fresh code up or the user retypes a dead code forever
            let newCode = e?.code === "challenge_reissued";
            if (!newCode && !client.hasChallenge && client.state === State.NeedsPin) {
              try {
                await withTimeout(client.requestChallenge(), 8000, "challenge timed out");
                newCode = true;
              } catch (err2) {
                logUp("verify.reissue.failed", "error", { err: errInfo(err2), state: client.state });
              }
            }
            logUp("verify.failed", "warn", { err: errInfo(e), newCode, state: client.state }, { trace, ctx });
            return sendResponse({
              ok: false,
              error: String(e?.message ?? e),
              newCode,
              state: client.state,
            });
          }
          logUp("verify.ok", "info", { state: client.state }, { trace, ctx });
          sendResponse({ ok: true, state: client.state });
          if (client.ready) flushPendingSaves();
          break;
        }

        case "getLogins": {
          const tab = await activeTab();
          if (!tab?.url) return sendResponse({ ok: false, error: "no active tab" });
          logUp("popup.logins", "debug", { tab: tab.id, url: safeUrl(tab.url), ready: client.ready });
          const logins = await client.getLoginNamesForURL(tab.id, tab.url);
          sendResponse({ ok: true, logins: uniqueByUsername(orderByMru(registrableHost(tab.url), logins)) });
          break;
        }

        case "fillOnPage": {
          const tab = await activeTab();
          if (!tab?.url) return sendResponse({ ok: false, error: "no active tab" });
          const host = registrableHost(tab.url);
          const scheme = schemeClass(tab.url, host);
          if (scheme === "http-public") {
            logUp("fill.refused", "warn", { host, scheme, why: "plain HTTP on a public host" }, { trace, ctx });
            return sendResponse({ ok: false, error: "refusing to fill on a non-HTTPS page", reason: "insecure-origin" });
          }
          let cred = pwCacheGet(host, msg.loginName?.username);
          const cacheHit = !!cred;
          if (!cred) {
            cred = await client.getPasswordForLoginName(tab.id, tab.url, msg.loginName);
            if (cred) pwCacheSet(host, cred);
          }
          logUp(
            "popup.fill.credential",
            cred ? "info" : "warn",
            {
              host,
              scheme,
              insecure: scheme === "http-local",
              user: maskUser(msg.loginName?.username),
              cacheHit,
              found: !!cred,
            },
            { trace, ctx },
          );
          let filled = false;
          let reply;
          if (cred) {
            // content script re-checks expectedHost before filling
            const resp = await chrome.tabs.sendMessage(tab.id, {
              type: "fill",
              username: cred.username,
              password: cred.password,
              expectedHost: host,
            });
            filled = !!resp?.filled;
            reply = resp;
            // tabs.sendMessage without a frameId answers from the first frame, so a
            // false here can mean "the top frame had nothing, an iframe did"
            logUp(
              "popup.fill.result",
              filled ? "info" : "warn",
              { host, scheme, user: maskUser(cred.username), filled, firstFrameSaid: summarizeResponse(resp) },
              { trace, ctx },
            );
            if (filled) {
              recordMru(host, cred.username);
              lastFillByTab.set(tab.id, { host, username: cred.username });
            }
          }
          let reason;
          if (!cred) reason = "no-credential";
          else if (!filled) reason = reply?.reason || "no-field";
          sendResponse({ ok: true, filled, reason });
          break;
        }

        case "refreshAndRefill": {
          // re-fill so a password changed in the Passwords app lands without re-clicking Fill
          pwCacheClear();
          const tab = await activeTab();
          const entry = tab?.id != null ? lastFillByTab.get(tab.id) : null;
          const host = tab?.url ? registrableHost(tab.url) : null;
          if (!entry || !host || entry.host !== host) {
            logUp("popup.refill.skip", "debug", {
              hasEntry: !!entry,
              host,
              entryHost: entry?.host,
              why: !entry ? "nothing filled in this tab" : "host changed",
            }, { trace, ctx });
            return sendResponse({ ok: true, refilled: false });
          }
          try {
            const cred = await client.getPasswordForLoginName(tab.id, tab.url, { username: entry.username });
            if (!cred) {
              logUp("popup.refill.missing", "warn", { host, user: maskUser(entry.username) }, { trace, ctx });
              return sendResponse({ ok: true, refilled: false });
            }
            pwCacheSet(host, cred);
            const resp = await chrome.tabs.sendMessage(tab.id, {
              type: "fill",
              username: cred.username,
              password: cred.password,
              expectedHost: host,
            });
            logUp("popup.refill", resp?.filled ? "info" : "warn", {
              host,
              user: maskUser(cred.username),
              refilled: !!resp?.filled,
              firstFrameSaid: summarizeResponse(resp),
            }, { trace, ctx });
            sendResponse({
              ok: true,
              refilled: !!resp?.filled,
              reason: resp?.filled ? undefined : resp?.reason || "no-field",
              username: cred.username,
            });
          } catch (e) {
            logUp("popup.refill.failed", "warn", { err: errInfo(e), host }, { trace, ctx });
            sendResponse({ ok: true, refilled: false, error: String(e?.message ?? e) });
          }
          break;
        }

        case "clearCache":
          logUp("cache.clear", "debug", { had: pwCacheSize(), fills: lastFillByTab.size }, { trace, ctx });
          pwCacheClear();
          sendResponse({ ok: true });
          break;

        case "disconnect":
          logUp("disconnect.request", "info", { state: client.state }, { trace, ctx });
          client.disconnect();
          sendResponse({ ok: true, state: client.state, stateReason: client.stateReason });
          break;

        default:
          logUp("msg.unknown", "warn", { type: msg?.type }, { trace, ctx });
          sendResponse({ ok: false, error: "unknown message" });
      }
    } catch (e) {
      logUp("msg.error", "error", { type: msg?.type, err: errInfo(e), portOpen: client.port !== undefined }, { trace, ctx });
      sendResponse({ ok: false, error: String(e?.message ?? e), state: client.state });
    }
  })();
  return true;
});
