import { DiagLog, safeUrl, serialize } from "./log.js";

const views = {
  nohelper: document.getElementById("view-nohelper"),
  pin: document.getElementById("view-pin"),
  connecting: document.getElementById("view-connecting"),
  unlocked: document.getElementById("view-unlocked"),
};
const dot = document.getElementById("dot");
const pinInput = document.getElementById("pin");
const pinError = document.getElementById("pin-error");
const refreshBtn = document.getElementById("refresh");

function show(name) {
  for (const [k, el] of Object.entries(views)) el.hidden = k !== name;
}

const pmToggle = document.getElementById("pm-toggle");
const pmNote = document.getElementById("pm-note");

function renderPmToggle() {
  const pref = chrome.privacy?.services?.passwordSavingEnabled;
  const row = document.getElementById("pm-row");
  if (!pref?.get) return;
  pref.get({}, (d) => {
    if (chrome.runtime.lastError || !d) return;
    row.hidden = false;
    pmToggle.checked = d.value === false;
    const controllable =
      d.levelOfControl === "controllable_by_this_extension" ||
      d.levelOfControl === "controlled_by_this_extension";
    pmToggle.disabled = !controllable;
    pmNote.textContent = controllable
      ? ""
      : d.levelOfControl === "controlled_by_other_extensions"
        ? "controlled by another extension"
        : "controlled by browser policy";
  });
}

pmToggle.addEventListener("change", () => {
  const pref = chrome.privacy?.services?.passwordSavingEnabled;
  if (!pref) return;
  const on = pmToggle.checked;
  chrome.storage?.local?.set({ suppressSaveBubble: on });
  // read back after writing, the browser can silently refuse
  const verify = () =>
    pref.get({}, (d) => {
      renderPmToggle();
      if (on && d && d.value !== false) {
        pmNote.textContent = "browser refused it - flip it in password settings below";
      }
    });
  if (on) pref.set({ value: false }, verify);
  else pref.clear({}, verify);
});

renderPmToggle();

// a user defaults write isnt a forced policy, only a config profile approved once in System Settings is
const policyToggle = document.getElementById("policy-toggle");
const policyNote = document.getElementById("policy-note");

function policyMsg(action) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendNativeMessage("com.openpasswords.policy", { action }, (resp) => {
        if (chrome.runtime.lastError) resolve({ error: chrome.runtime.lastError.message });
        else resolve(resp || { error: "no reply" });
      });
    } catch (e) {
      resolve({ error: String(e) });
    }
  });
}

async function renderPolicyToggle() {
  const r = await policyMsg("get");
  if (r.error || !r.ok) {
    policyToggle.disabled = true;
    policyNote.textContent = "needs the policy helper - run native/install.sh";
    return;
  }
  policyToggle.disabled = false;
  policyToggle.checked = !!r.hidden;
  policyNote.textContent = "";
}

policyToggle.addEventListener("change", async () => {
  const on = policyToggle.checked;
  policyToggle.disabled = true;
  const r = await policyMsg(on ? "set" : "clear");
  policyToggle.disabled = false;
  if (r.error || !r.ok) {
    policyNote.textContent = "helper failed - run native/install.sh";
    policyToggle.checked = !on;
    return;
  }
  // the profile only sticks once approved, reflect the real forced state
  policyToggle.checked = !!r.hidden;
  if (on && !r.hidden) policyNote.textContent = "approve the profile in System Settings, then reopen this popup";
  else if (!on && r.hidden) policyNote.textContent = "remove the profile in System Settings, then reopen this popup";
  else policyNote.textContent = "";
});

renderPolicyToggle();

// credit-card autofill stays untouched so google pay keeps working
const afToggle = document.getElementById("af-toggle");
const afNote = document.getElementById("af-note");

function renderAfToggle() {
  const pref = chrome.privacy?.services?.autofillAddressEnabled;
  const row = document.getElementById("af-row");
  if (!pref?.get) return;
  pref.get({}, (d) => {
    if (chrome.runtime.lastError || !d) return;
    row.hidden = false;
    afToggle.checked = d.value === false;
    const controllable =
      d.levelOfControl === "controllable_by_this_extension" ||
      d.levelOfControl === "controlled_by_this_extension";
    afToggle.disabled = !controllable;
    afNote.textContent = controllable ? "" : "controlled elsewhere";
  });
}

afToggle.addEventListener("change", () => {
  const pref = chrome.privacy?.services?.autofillAddressEnabled;
  if (!pref) return;
  const on = afToggle.checked;
  chrome.storage?.local?.set({ suppressAddressAutofill: on });
  const verify = () =>
    pref.get({}, (d) => {
      renderAfToggle();
      if (on && d && d.value !== false) {
        afNote.textContent = "browser refused it - flip it in autofill settings";
      }
    });
  if (on) pref.set({ value: false }, verify);
  else pref.clear({}, verify);
});

renderAfToggle();

const pkToggle = document.getElementById("pk-toggle");
chrome.storage?.local?.get({ hidePasskeys: false }, (d) => {
  pkToggle.checked = !!d.hidePasskeys;
});
pkToggle.addEventListener("change", () => {
  chrome.storage?.local?.set({ hidePasskeys: pkToggle.checked });
});

// off by default, needs the browser allowed to automate System Events and macOS asks the first time
const autoPairToggle = document.getElementById("autopair-toggle");
const autoPairNote = document.getElementById("autopair-note");
chrome.storage?.local?.get({ autoPair: false }, (d) => {
  autoPairToggle.checked = !!d.autoPair;
});
autoPairToggle.addEventListener("change", async () => {
  const on = autoPairToggle.checked;
  chrome.storage?.local?.set({ autoPair: on });
  autoPairNote.textContent = "";
  if (!on) return;
  autoPairNote.textContent = "checking…";
  const r = await send({ type: "autoPairCheck" });
  if (r?.ok) {
    autoPairNote.textContent = "on - the next code your Mac shows gets entered for you";
  } else if (/not found|forbidden|host/i.test(r?.error || "")) {
    autoPairNote.textContent = "needs the reader helper - run native/install.sh, then restart the browser";
  } else {
    autoPairNote.textContent = r?.error || "the reader could not reach System Events";
  }
});

function renderAutoPairError(err) {
  if (!autoPairToggle.checked || !err) return;
  autoPairNote.textContent = `last attempt: ${err}`;
}

function setDot(state) {
  dot.className = "dot";
  if (state === "unlocked") dot.classList.add("ok");
  else if (state === "needs_pin") dot.classList.add("warn");
  else if (state === "no_helper") dot.classList.add("err");
}

let uiTraceSeq = 0;
function newUiTrace() {
  uiTraceSeq += 1;
  return `ui-${uiTraceSeq.toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
}

// every popup action carries a trace so the whole chain (popup -> worker -> helper)
// can be read as one thread in the diagnostics export
function send(msg) {
  const trace = msg.trace || newUiTrace();
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage({ ...msg, trace }, (res) => {
        const err = chrome.runtime.lastError?.message;
        resolve(err ? { ok: false, error: err } : res);
      });
    } catch (e) {
      resolve({ ok: false, error: String(e?.message ?? e) });
    }
  });
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

let lastState = "disconnected";
let stateReason = "";

async function render(state) {
  lastState = state;
  setDot(state);
  refreshBtn.hidden = state !== "unlocked" && state !== "needs_pin";
  if (state === "no_helper") return show("nohelper");
  if (state === "disconnected") return show("connecting");
  if (state === "needs_pin") {
    show("pin");
    pinInput.focus();
    return;
  }
  if (state === "unlocked") {
    await renderLogins();
    show("unlocked");
    renderCodes();
    renderAppLinks();
    return;
  }
  // unknown state must never leave every view hidden (blank popup)
  show("connecting");
}

// one sentence the user can act on, instead of a button that does nothing
function fillErrorText(res) {
  const reason = String(res?.reason || "");
  const err = String(res?.error || "");
  if (/insecure-origin|non-HTTPS/i.test(err) || reason === "insecure-origin") {
    return "Not filled: this page is plain HTTP, so the password stays in the vault.";
  }
  if (/origin mismatch/i.test(err)) return "Not filled: the page address changed while filling.";
  if (/not unlocked|not connected|locked/i.test(err)) return "Not filled: the vault is locked.";
  if (/timeout|did not answer|no response/i.test(err)) return "Not filled: Apple's helper did not answer.";
  if (reason === "no-credential") return "Not filled: no saved password for this account on this site.";
  if (reason === "no-field" || reason === "partial") return "Not filled: this page has no password field I can safely target.";
  return err ? `Not filled: ${err}` : "Not filled.";
}

async function renderLogins() {
  const tab = await activeTab();
  document.getElementById("site").textContent = tab?.url ? new URL(tab.url).hostname : "";
  const list = document.getElementById("logins");
  const none = document.getElementById("nologins");
  list.innerHTML = "";
  none.hidden = true;

  const res = await send({ type: "getLogins", tabId: tab.id, url: tab.url });
  if (!res?.ok) {
    none.hidden = false;
    none.textContent = res?.error ?? "Couldn't load logins.";
    return;
  }
  if (!res.logins.length) {
    none.hidden = false;
    return;
  }
  for (const login of res.logins) {
    const li = document.createElement("li");
    const u = document.createElement("span");
    u.className = "u";
    u.textContent = login.username || "(no username)";
    const fill = document.createElement("button");
    fill.textContent = "Fill";
    fill.addEventListener("click", async () => {
      fill.disabled = true;
      const r = await send({ type: "fillOnPage", tabId: tab.id, url: tab.url, loginName: login });
      if (r?.ok && r.filled) window.close();
      else {
        fill.disabled = false;
        flashNote(fillErrorText(r));
      }
    });
    li.append(u, fill);
    list.appendChild(li);
  }
}

async function renderCodes() {
  const list = document.getElementById("codes");
  list.innerHTML = "";
  list.hidden = true;
  const res = await send({ type: "getOneTimeCodes" });
  if (!res?.ok || !res.rows?.length) return;
  for (const row of res.rows) {
    const li = document.createElement("li");
    const text = document.createElement("span");
    text.className = "u";
    const label = document.createElement("span");
    label.className = "code-label";
    label.textContent =
      row.source === "totp"
        ? row.domain
          ? `Verification code for ${row.domain}`
          : "Verification code"
        : "Code from Messages";
    text.appendChild(label);
    if (row.username) {
      const sub = document.createElement("span");
      sub.className = "subnote";
      sub.textContent = row.username;
      text.appendChild(sub);
    }
    const fill = document.createElement("button");
    fill.textContent = "Fill";
    fill.addEventListener("click", async () => {
      fill.disabled = true;
      const r = await send({ type: "fillOneTimeCode", id: row.id });
      if (r?.ok && r.filled) return window.close();
      if (r?.ok && r.code) {
        fill.replaceWith(codeBadge(r.code));
        return;
      }
      fill.disabled = false;
      flashNote(r?.error ? `Couldn't read the code: ${r.error}` : "Couldn't read the code");
    });
    li.append(text, fill);
    list.appendChild(li);
  }
  list.hidden = false;
}

function codeBadge(code) {
  const b = document.createElement("span");
  b.className = "code-value";
  b.textContent = code;
  b.title = "Current code";
  return b;
}

let caps = {};
let pageTotpUri = null;
async function renderAppLinks() {
  document.getElementById("new-login").hidden = !caps.newPasswordSheet;
  const totpBtn = document.getElementById("setup-totp");
  totpBtn.hidden = true;
  pageTotpUri = null;
  if (!caps.setUpTotp) return;
  try {
    const tab = await activeTab();
    if (!tab?.id) return;
    const r = await chrome.tabs.sendMessage(tab.id, { type: "findTotpUri" }, { frameId: 0 });
    const uri = r?.uris?.[0];
    if (!uri) return;
    pageTotpUri = uri;
    totpBtn.hidden = false;
  } catch (_) {}
}

document.getElementById("open-app").addEventListener("click", async () => {
  await send({ type: "openPasswordsApp", mode: "search" });
  window.close();
});
document.getElementById("new-login").addEventListener("click", async () => {
  await send({ type: "openPasswordsApp", mode: "new" });
  window.close();
});
document.getElementById("setup-totp").addEventListener("click", async () => {
  if (!pageTotpUri) return;
  await send({ type: "openPasswordsApp", mode: "totp", uri: pageTotpUri });
  window.close();
});

document.getElementById("verify").addEventListener("click", async () => {
  pinError.hidden = true;
  const pin = pinInput.value.trim();
  if (pin.length < 4) return;
  const res = await send({ type: "verifyPin", pin });
  if (res?.ok) render(res.state);
  else {
    // a failed attempt spends the code, so the background put a fresh one on the Mac
    const base = res?.error ?? "Verification failed.";
    pinError.textContent = res?.newCode ? `${base} - enter the new code on your Mac` : base;
    pinError.hidden = false;
    pinInput.value = "";
    pinInput.focus();
  }
});

pinInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") document.getElementById("verify").click();
});
pinInput.addEventListener("input", () => {
  if (pinInput.value.trim().length === 6) document.getElementById("verify").click();
});

let noteTimer = null;
function flashNote(text) {
  const el = document.getElementById("refresh-note");
  el.textContent = text;
  el.hidden = false;
  clearTimeout(noteTimer);
  noteTimer = setTimeout(() => (el.hidden = true), 2500);
}

refreshBtn.addEventListener("click", async () => {
  refreshBtn.disabled = true;
  refreshBtn.classList.add("spinning");
  if (lastState === "needs_pin") {
    pinError.hidden = true;
    pinInput.value = "";
    const res = await send({ type: "requestChallenge" });
    if (res?.ok) render(res.state);
    else {
      pinError.textContent = res?.error ?? "Couldn't request a code.";
      pinError.hidden = false;
    }
  } else {
    const r = await send({ type: "refreshAndRefill" });
    await renderLogins();
    renderCodes();
    if (r?.refilled) flashNote(`Re-filled ${r.username} with the latest password`);
    else if (r?.reason) flashNote(fillErrorText(r));
    else flashNote("Passwords refreshed");
  }
  refreshBtn.classList.remove("spinning");
  refreshBtn.disabled = false;
});

document.getElementById("newcode").addEventListener("click", async () => {
  pinError.hidden = true;
  const res = await send({ type: "requestChallenge" });
  if (res?.ok) render(res.state);
  else {
    pinError.textContent = res?.error ?? "Couldn't request a code.";
    pinError.hidden = false;
  }
});

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "state") {
    // capabilities arrive with the hello, which precedes the first state change
    send({ type: "getState" }).then((r) => {
      caps = r?.caps || caps;
      stateReason = r?.stateReason || stateReason;
      render(msg.state);
    });
    renderDiag();
  }
});

(async () => {
  const res = await send({ type: "getState" });
  caps = res?.caps || {};
  stateReason = res?.stateReason || stateReason;
  renderAutoPairError(res?.autoPairError);
  let state = res?.state ?? "disconnected";
  if (state === "needs_pin") {
    // never on top of a code thats already showing, a second prompt kills the first code
    const ch = await send({ type: "requestChallenge", ifNeeded: true });
    state = ch?.state ?? state;
  }
  render(state);
  renderDiag();
  // the page the popup was opened on: the "which site" half of every report
  const tab = await activeTab();
  logUi("popup.open", {
    state,
    reason: stateReason,
    page: tab?.url ? safeUrl(tab.url) : undefined,
    tab: tab?.id,
    incognito: (() => {
      try {
        return chrome.extension?.inIncognitoContext === true;
      } catch (_) {
        return false;
      }
    })(),
  });
})();

// --- diagnostics panel ---------------------------------------------------------
// Reads the worker's buffer (chrome.storage.session), never writes events itself:
// everything the popup does is already recorded by the worker as msg.in/msg.out.
function logUi(t, d) {
  try {
    chrome.runtime.sendMessage({ type: "log", events: [{ t, lvl: "info", d }] }).catch(() => {});
  } catch (_) {}
}

function diagNote(text) {
  document.getElementById("diag-note").textContent = text;
  if (!text) return;
  setTimeout(() => {
    const el = document.getElementById("diag-note");
    if (el && el.textContent === text) el.textContent = "";
  }, 4000);
}

function describeEvent(ev) {
  const d = ev?.d || {};
  const bits = [];
  if (d.error) bits.push(String(d.error));
  if (d.err?.msg) bits.push(String(d.err.msg));
  if (d.err?.name) bits.push(String(d.err.name));
  if (d.why) bits.push(String(d.why));
  if (d.reason) bits.push(String(d.reason));
  if (d.state) bits.push(`state=${d.state}`);
  return bits.join(" · ").slice(0, 220);
}

async function diagSnapshotNow() {
  const log = new DiagLog();
  await log.load({ scope: "popup", ver: chrome.runtime.getManifest().version });
  return log.snapshot({
    scope: "popup",
    ver: chrome.runtime.getManifest().version,
    incognito: (() => {
      try {
        return chrome.extension?.inIncognitoContext === true;
      } catch (_) {
        return false;
      }
    })(),
    browser: navigator.userAgent,
    lastState: lastState,
    stateReason: stateReason,
  });
}

async function renderDiag() {
  let snap;
  try {
    snap = await diagSnapshotNow();
  } catch (e) {
    document.getElementById("diag-summary").textContent = `could not read the log: ${e?.message ?? e}`;
    return;
  }
  const counts = snap.counts || { events: 0, errors: 0 };
  document.getElementById("diag-summary").textContent = [
    `${counts.events} events`,
    `${counts.errors} problems`,
    counts.droppedOldest ? `${counts.droppedOldest} dropped` : null,
    `last state: ${lastState}${stateReason ? ` (${stateReason})` : ""}`,
    snap.meta?.incognito ? "incognito" : null,
  ]
    .filter(Boolean)
    .join(" · ");
  const errors = snap.errors || [];
  const last = errors[errors.length - 1];
  const errEl = document.getElementById("diag-error");
  errEl.textContent = last ? `last problem ${last.t}: ${describeEvent(last)}` : "no problems recorded";
  errEl.style.opacity = last ? "1" : "0.6";
}

document.getElementById("diag-copy").addEventListener("click", async () => {
  try {
    const text = serialize(await diagSnapshotNow());
    await navigator.clipboard.writeText(text);
    diagNote(`copied ${text.length} chars (contains hostnames, no passwords)`);
  } catch (e) {
    diagNote(`copy failed: ${e?.message ?? e}`);
  }
});

document.getElementById("diag-export").addEventListener("click", async () => {
  try {
    const text = serialize(await diagSnapshotNow());
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `open-passwords-diag-${stamp}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    diagNote("exported (contains hostnames, no passwords)");
  } catch (e) {
    diagNote(`export failed: ${e?.message ?? e}`);
  }
});

document.getElementById("diag-clear").addEventListener("click", async () => {
  const log = new DiagLog();
  await log.clear();
  diagNote("log cleared");
  renderDiag();
});

const verboseToggle = document.getElementById("verbose-toggle");
chrome.storage?.local?.get({ verboseDiagnostics: true }, (d) => {
  verboseToggle.checked = d.verboseDiagnostics !== false;
});
verboseToggle.addEventListener("change", () => {
  chrome.storage?.local?.set({ verboseDiagnostics: verboseToggle.checked });
  diagNote(verboseToggle.checked ? "verbose on: every focus and native call is recorded" : "verbose off: only problems are recorded");
});

document.getElementById("diag").addEventListener("toggle", (e) => {
  if (e.target.open) renderDiag();
});
