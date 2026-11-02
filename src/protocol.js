// ported from au2001/icloud-passwords-firefox (Apache-2.0), see NOTICE

import { SRPSession, SecretSessionVersion, MSGType } from "./srp.js";
import {
  bytesToBase64,
  base64ToBytes,
  bytesToUtf8,
  bigIntToBytes,
  bytesToBigInt,
  constantTimeEqual,
  QueryStatus,
  queryStatusError,
} from "./crypto.js";
import { errInfo, safeUrl, maskUser } from "./log.js";

const NATIVE_HOST = "com.apple.passwordmanager";
const BROWSER_NAME = "Chrome";
const VERSION = "1.0";
// past this we re-prompt instead of verifying against a code the user lost track of
const CHALLENGE_TTL_MS = 3 * 60_000;

// callers show "new code" wording for this, retyping the old code can never work
function challengeError(message) {
  const e = new Error(message);
  e.code = "challenge_reissued";
  return e;
}

// numbering matches the helper's own ExtensionCommand enum (and apple's extension)
export const Command = {
  END: 0,
  HANDSHAKE: 2,
  SET_ICON_AND_TITLE: 3,
  GET_LOGIN_NAMES_FOR_URL: 4,
  GET_PASSWORD_FOR_LOGIN_NAME: 5,
  SET_PASSWORD_FOR_LOGIN_NAME_URL: 6,
  NEW_ACCOUNT_FOR_URL: 7,
  TAB_EVENT: 8,
  PASSWORDS_DISABLED: 9,
  RELOGIN_NEEDED: 10,
  LAUNCH_PASSWORDS_APP: 13, // also carries "new password sheet" and "set up TOTP" variants
  GET_CAPABILITIES: 14,
  ONE_TIME_CODE_AVAILABLE: 15, // helper -> us, unsolicited: a code just arrived (Messages)
  GET_ONE_TIME_CODES: 16,
  DID_FILL_ONE_TIME_CODE: 17, // read the current TOTP value right before filling it
  SET_UP_TOTP_GENERATOR: 18, // status reply to the set-up-TOTP variant of cmd 13
  OPEN_URL_IN_SAFARI: 1984,
};

const QueryId = {
  [4]: "CmdGetLoginNames4URL",
  [5]: "CmdGetPassword4LoginName",
  [16]: "CmdGetOneTimeCodes",
  [17]: "CmdDidFillOneTimeCode",
};

function cmdName(cmd) {
  for (const [name, value] of Object.entries(Command)) if (value === cmd) return name;
  return `cmd${cmd}`;
}

function hostParam(hostname) {
  // already a bare hostname, safeUrl only normalizes it
  return hostname ? safeUrl(`https://${hostname}/`).split("/")[0] : undefined;
}

const Action = { UPDATE: 1, SEARCH: 2, ADD_NEW: 3, MAYBE_ADD: 4, GHOST_SEARCH: 5 };

export const State = {
  Disconnected: "disconnected",
  NeedsPin: "needs_pin",
  Unlocked: "unlocked",
  NoHelper: "no_helper",
};

function jsonToBase64(obj) {
  return bytesToBase64(new TextEncoder().encode(JSON.stringify(obj)));
}

// totp entries can arrive without a code, the value is read at fill time
function normalizeOtpEntries(entries) {
  return (Array.isArray(entries) ? entries : [])
    .map((e) => ({
      source: String(e.source || ""),
      username: e.username || "",
      domain: e.domain || "",
      code: e.code != null ? String(e.code) : "",
    }))
    .filter((e) => e.code || e.source === "totp");
}

export class ApplePasswords {
  constructor({ log } = {}) {
    this.port = undefined;
    this.session = undefined;
    this.capabilities = undefined;
    this.state = State.Disconnected;
    this.stateReason = undefined;
    // set by the background so every native call carries the user action that caused it
    this.trace = undefined;
    this._log = typeof log === "function" ? log : () => {};
    this._waiters = new Map();
    this._onState = () => {};
    this._onOneTimeCode = () => {};
    this._challengeAt = 0;
    this._challengeGen = 0;
    this._challengePending = undefined;
    // replies carry no correlation id, so same-cmd requests collide. serialize everything
    this._lock = Promise.resolve();
  }

  _withLock(fn) {
    const run = this._lock.then(fn, fn);
    this._lock = run.then(
      () => {},
      () => {},
    );
    return run;
  }

  _logEvent(t, lvl, d) {
    try {
      this._log({ t, lvl, d: { ...d, trace: this.trace } });
    } catch (_) {}
  }

  onStateChange(fn) {
    this._onState = fn;
  }

  onOneTimeCodeAvailable(fn) {
    this._onOneTimeCode = fn;
  }

  // default false so an older helper hides the feature instead of getting a command it cant handle
  get canFillOneTimeCodes() {
    return this.capabilities?.canFillOneTimeCodes === true;
  }
  get canOpenPasswordsAppToNewPasswordSheet() {
    return this.capabilities?.canOpenPasswordsAppToNewPasswordSheet === true;
  }
  get canSetUpTotp() {
    return this.capabilities?.scanForOTPURI === true;
  }
  get canSaveAccountWithEmptyUserName() {
    return this.capabilities?.canSaveAccountWithEmptyUserName === true;
  }

  _setState(s, why) {
    const from = this.state;
    if (from === s) {
      if (why) this._logEvent("state", "debug", { from, to: s, why, unchanged: true });
      return;
    }
    this.state = s;
    this.stateReason = why || undefined;
    this._logEvent("state", s === State.NoHelper || s === State.Disconnected ? "warn" : "info", {
      from,
      to: s,
      why,
      connected: this.port !== undefined,
      hasSession: this.session !== undefined,
    });
    try {
      this._onState(s);
    } catch (_) {}
  }

  get ready() {
    return (
      this.port !== undefined &&
      this.session !== undefined &&
      this.session.sharedKey !== undefined &&
      this.state === State.Unlocked
    );
  }

  _send(cmd, body = {}, timeoutMs = 5000) {
    if (!this.port) throw new Error("connection closed");
    const name = cmdName(cmd);
    // a second request on the same cmd would steal the first one's reply
    if (this._waiters.has(cmd)) {
      this._logEvent("native.reject", "warn", { cmd: name, why: "another request is already in flight" });
      return Promise.reject(new Error("another request is already in flight"));
    }
    const started = Date.now();
    const meta = { tab: body.tabId, frame: body.frameId, host: hostParam(body.url) };
    this._logEvent("native.start", "debug", { cmd: name, timeout: timeoutMs == null ? "none" : timeoutMs, ...meta });
    return new Promise((resolve, reject) => {
      const entry = {
        resolve: (message) => {
          this._logEvent("native.done", "debug", { cmd: name, dur: Date.now() - started, outcome: "reply", ...meta });
          resolve(message);
        },
        reject: (e) => {
          this._logEvent("native.done", "warn", { cmd: name, dur: Date.now() - started, outcome: "error", err: errInfo(e), ...meta });
          reject(e);
        },
        timer: null,
      };
      entry.timer =
        timeoutMs == null
          ? null
          : setTimeout(() => {
              if (this._waiters.get(cmd) === entry) this._waiters.delete(cmd);
              this._logEvent("native.done", "warn", { cmd: name, dur: Date.now() - started, outcome: "timeout", ...meta });
              reject(new Error("timeout waiting for response"));
            }, timeoutMs);
      this._waiters.set(cmd, entry);
      try {
        this.port.postMessage({ cmd, ...body });
      } catch (e) {
        if (entry.timer) clearTimeout(entry.timer);
        if (this._waiters.get(cmd) === entry) this._waiters.delete(cmd);
        this._logEvent("native.done", "error", { cmd: name, dur: Date.now() - started, outcome: "post-failed", err: errInfo(e), ...meta });
        reject(e);
      }
    });
  }

  _dispatch(message) {
    const w = this._waiters.get(message.cmd);
    if (w) {
      this._waiters.delete(message.cmd);
      if (w.timer) clearTimeout(w.timer);
      w.resolve(message);
    } else if (
      message.cmd === Command.ONE_TIME_CODE_AVAILABLE ||
      message.cmd === Command.PASSWORDS_DISABLED ||
      message.cmd === Command.RELOGIN_NEEDED
    ) {
      // these arrive without a request, so having no waiter is normal
      this._logEvent("native.unsolicited", "debug", { cmd: cmdName(message.cmd) });
    } else {
      // a reply nobody waits for: the waiter timed out first, which is exactly the
      // kind of desync that later looks like "the helper never answers"
      this._logEvent("native.late-reply", "warn", { cmd: cmdName(message.cmd), why: "no waiter (arrived after timeout?)" });
    }
    if (message.cmd === Command.PASSWORDS_DISABLED || message.cmd === Command.RELOGIN_NEEDED) {
      this._logEvent("native.session-lost", "warn", { cmd: cmdName(message.cmd) });
      this.session = undefined;
      // the port stays open, so a plain reconnect has to re-issue a handshake
      this._setState(State.NeedsPin, `helper sent ${cmdName(message.cmd)}`);
    }
    if (message.cmd === Command.ONE_TIME_CODE_AVAILABLE && !w) {
      try {
        this._onOneTimeCode();
      } catch (_) {}
    }
  }

  // never resets an unlocked session, apple's extension re-pairs on every connect
  async connect() {
    if (this.port) {
      this._logEvent("connect", "debug", { skipped: "port already open", state: this.state });
      return;
    }
    this._logEvent("connect", "info", { host: NATIVE_HOST });
    return new Promise((resolve, reject) => {
      let port;
      try {
        port = chrome.runtime.connectNative(NATIVE_HOST);
      } catch (e) {
        this._logEvent("connect.failed", "error", { err: errInfo(e), stage: "connectNative" });
        this._setState(State.NoHelper, "connectNative threw");
        return reject(e);
      }
      this.port = port;

      port.onMessage.addListener((msg) => this._dispatch(msg));
      port.onDisconnect.addListener(() => {
        const err = chrome.runtime.lastError?.message;
        this._logEvent("disconnect", "warn", { lastError: err ? String(err) : "(none)" });
        this.port = undefined;
        this.session = undefined;
        this._waiters.clear();
        if (err && /not found|forbidden|host/i.test(err)) this._setState(State.NoHelper, `native host error: ${err}`);
        else this._setState(State.Disconnected, "port disconnected");
      });

      this._send(Command.GET_CAPABILITIES)
        .then((reply) => {
          this.capabilities = reply.capabilities ?? {};
          this._logEvent("capabilities", "info", {
            keys: Object.keys(this.capabilities),
            secretSessionVersion: this.capabilities.secretSessionVersion,
            shouldUseBase64: this.capabilities.shouldUseBase64,
            canFillOneTimeCodes: this.capabilities.canFillOneTimeCodes,
            scanForOTPURI: this.capabilities.scanForOTPURI,
            canOpenPasswordsAppToNewPasswordSheet: this.capabilities.canOpenPasswordsAppToNewPasswordSheet,
          });
          // helper negotiates the version per handshake via PROTO, so only reject an explicit non-RFC demand
          if (
            this.capabilities.secretSessionVersion !== undefined &&
            this.capabilities.secretSessionVersion !== SecretSessionVersion.SRPWithRFCVerification
          ) {
            this._logEvent("connect.failed", "error", {
              stage: "capabilities",
              secretSessionVersion: this.capabilities.secretSessionVersion,
              expected: SecretSessionVersion.SRPWithRFCVerification,
              note: "port stays open, retry then early-returns",
            });
            return reject(new Error("unsupported capabilities (expected SRP RFC verification)"));
          }
          this.session = new SRPSession(this.capabilities.shouldUseBase64);
          this._setState(State.NeedsPin, "capabilities received");
          resolve();
        })
        .catch((e) => {
          this._logEvent("connect.failed", "error", { stage: "capabilities", err: errInfo(e) });
          reject(e);
        });
    });
  }

  // the code on the Mac only belongs to the newest challenge
  get hasChallenge() {
    return (
      this.state === State.NeedsPin &&
      this.session !== undefined &&
      this.session.serverPublicKey !== undefined &&
      this.session.salt !== undefined &&
      Date.now() - this._challengeAt < CHALLENGE_TTL_MS
    );
  }

  // ifNeeded keeps a live prompt, a second code on screen invalidates the one the user is reading
  requestChallenge({ ifNeeded = false } = {}) {
    if (!this.session) return Promise.reject(new Error("not connected"));
    if (ifNeeded && (this.hasChallenge || this.state === State.Unlocked)) return Promise.resolve(false);
    // two prompts would race and only the last code works
    if (this._challengePending) return this._challengePending;
    const p = this._withLock(() => this._issueChallenge());
    this._challengePending = p;
    const clear = () => {
      if (this._challengePending === p) this._challengePending = undefined;
    };
    p.then(clear, clear);
    return p;
  }

  async _issueChallenge() {
    this.session.serverPublicKey = undefined;
    this.session.salt = undefined;
    this.session.sharedKey = undefined;
    this._challengeGen++;
    this._logEvent("challenge.request", "info", { gen: this._challengeGen });

    const reply = await this._send(Command.HANDSHAKE, {
      msg: {
        QID: "m0",
        PAKE: jsonToBase64({
          TID: this.session.username,
          MSG: MSGType.ClientKeyExchange,
          A: this.session.serialize(this.session.clientPublicKeyBytes),
          VER: VERSION,
          PROTO: [SecretSessionVersion.SRPWithRFCVerification],
        }),
        HSTBRSR: BROWSER_NAME,
      },
    });

    const pake = JSON.parse(bytesToUtf8(base64ToBytes(reply.payload.PAKE)));
    if (pake.TID !== this.session.username) throw new Error("challenge for another session");
    if (pake.ErrCode !== undefined) throw new Error(`server hello error ${pake.ErrCode}`);
    if (pake.MSG.toString() !== MSGType.ServerKeyExchange.toString()) throw new Error("unexpected server message");
    if (pake.PROTO !== SecretSessionVersion.SRPWithRFCVerification) throw new Error("unsupported protocol");

    const B = bytesToBigInt(this.session.deserialize(pake.B));
    const s = this.session.deserialize(pake.s);
    this.session.setServerPublicKey(B, s);
    this._challengeAt = Date.now();
    this._logEvent("challenge.issued", "info", { gen: this._challengeGen, proto: pake.PROTO });
    this._setState(State.NeedsPin, "challenge issued");
    return true;
  }

  // a PIN only matches the challenge it was shown for, so re-issue and ask for the new code
  async verifyPin(pin) {
    if (!this.session) throw new Error("not connected");
    if (!this.hasChallenge) {
      this._logEvent("verify", "warn", { why: "no live challenge", pinLen: String(pin || "").length });
      await this.requestChallenge();
      throw challengeError("Enter the new code your Mac is showing now");
    }
    const gen = this._challengeGen;
    this._logEvent("verify", "info", { gen, pinLen: String(pin || "").length });
    return this._withLock(async () => {
      // re-issued while queued, typed code is for the old prompt
      if (gen !== this._challengeGen) throw challengeError("Enter the new code your Mac is showing now");
      // declared outside the try so the catch can report the helper's ErrCode
      let pake;
      try {
        await this.session.setSharedKey(pin);
        const m = await this.session.computeM();

        const reply = await this._send(Command.HANDSHAKE, {
          msg: {
            QID: "m2",
            PAKE: jsonToBase64({
              TID: this.session.username,
              MSG: MSGType.ClientVerification,
              M: this.session.serialize(m, false),
            }),
          },
        });

        pake = JSON.parse(bytesToUtf8(base64ToBytes(reply.payload.PAKE)));
        if (pake.TID !== this.session.username) throw new Error("verification for another session");
        if (pake.MSG.toString() !== MSGType.ServerVerification.toString()) throw new Error("unexpected server message");
        if (pake.ErrCode === 1) throw new Error("Incorrect code");
        if (pake.ErrCode !== 0 && pake.ErrCode !== undefined) throw new Error(`verification error ${pake.ErrCode}`);

        const hamk = await this.session.computeHMAC(m);
        if (!constantTimeEqual(this.session.deserialize(pake.HAMK), hamk))
          throw new Error("server HAMK mismatch");

        this._logEvent("verify.ok", "info", { gen });
        this._setState(State.Unlocked, "PIN verified");
      } catch (e) {
        this._logEvent("verify.failed", "warn", { gen, err: errInfo(e), errCode: pake?.ErrCode });
        // helper burns the challenge on a failed verify, drop it so the next attempt gets a fresh prompt
        if (this.session) {
          this.session.sharedKey = undefined;
          this.session.serverPublicKey = undefined;
          this.session.salt = undefined;
        }
        this._challengeAt = 0;
        throw e;
      }
    });
  }

  async _encryptedQuery(cmd, tabId, hostname, payloadBody, timeoutMs, frameId = 0) {
    const sdata = this.session.serialize(await this.session.encrypt(payloadBody));
    const body = {
      tabId,
      frameId,
      payload: { QID: QueryId[cmd], SMSG: JSON.stringify({ TID: this.session.username, SDATA: sdata }) },
    };
    // one-time-code queries carry their URLs inside the encrypted body
    if (hostname != null) body.url = hostname;
    const reply = await this._send(cmd, body, timeoutMs);

    let smsg = reply.payload.SMSG;
    if (typeof smsg === "string") smsg = JSON.parse(smsg);
    if (smsg.TID !== this.session.username) throw new Error("response for another session");
    const data = await this.session.decrypt(this.session.deserialize(smsg.SDATA));
    return JSON.parse(bytesToUtf8(data));
  }

  _logQuery(cmd, hostname, res, extra) {
    this._logEvent("query", res.STATUS === QueryStatus.Success ? "debug" : "warn", {
      cmd: QueryId[cmd] || cmdName(cmd),
      host: hostParam(hostname),
      status: res.STATUS,
      ...extra,
    });
  }

  async getLoginNamesForURL(tabId, url) {
    if (!this.ready) throw new Error("not unlocked");
    const { hostname } = new URL(url);
    return this._withLock(async () => {
      const res = await this._encryptedQuery(
        Command.GET_LOGIN_NAMES_FOR_URL,
        tabId,
        hostname,
        { ACT: Action.GHOST_SEARCH, URL: hostname },
        5000,
      );
      this._logQuery(Command.GET_LOGIN_NAMES_FOR_URL, hostname, res, { n: (res.Entries ?? []).length });
      if (res.STATUS === QueryStatus.Success)
        return (res.Entries ?? []).map((e) => ({ username: e.USR, sites: e.sites }));
      if (res.STATUS === QueryStatus.NoResults) return [];
      throw queryStatusError(res.STATUS);
    });
  }

  async getPasswordForLoginName(tabId, url, loginName) {
    if (!this.ready) throw new Error("not unlocked");
    const { hostname } = new URL(url);
    return this._withLock(async () => {
      const res = await this._encryptedQuery(
        Command.GET_PASSWORD_FOR_LOGIN_NAME,
        tabId,
        // query by frame hostname, never loginName.sites which a page could point at another origin
        hostname,
        { ACT: Action.SEARCH, URL: hostname, USR: loginName.username },
        null, // no timeout, helper may require Touch ID here
      );
      if (res.STATUS === QueryStatus.Success) {
        const e = (res.Entries ?? [])[0];
        // never the value, only its length and the account it belongs to
        this._logQuery(Command.GET_PASSWORD_FOR_LOGIN_NAME, hostname, res, {
          n: (res.Entries ?? []).length,
          requested: maskUser(loginName.username),
          got: e ? maskUser(e.USR) : "(none)",
          pwLen: e?.PWD ? String(e.PWD).length : 0,
        });
        if (!e) return undefined;
        // reply is USR/PWD/customTitle/highLevelDomain/sites, no note or OTP seed
        return { username: e.USR, password: e.PWD, sites: e.sites };
      }
      this._logQuery(Command.GET_PASSWORD_FOR_LOGIN_NAME, hostname, res, { requested: maskUser(loginName.username) });
      if (res.STATUS === QueryStatus.NoResults) return undefined;
      throw queryStatusError(res.STATUS);
    });
  }

  // ACT maybeAdd lets the helper decide add-vs-update and drive the native save prompt
  async saveLogin(tabId, url, username, password) {
    if (!this.ready) throw new Error("not unlocked");
    if (!password) throw new Error("no password to save");
    const { hostname } = new URL(url);
    return this._withLock(async () => {
      const sdata = this.session.serialize(
        await this.session.encrypt({
          ACT: Action.MAYBE_ADD,
          URL: "",
          USR: "",
          PWD: "",
          NURL: hostname,
          NUSR: username ?? "",
          NPWD: password,
        }),
      );
      const body = {
        tabId,
        frameId: 0,
        payload: {
          QID: "CmdNewAccount4URL",
          SMSG: JSON.stringify({ TID: this.session.username, SDATA: sdata }),
        },
      };
      this._logEvent("save.request", "info", { host: hostParam(hostname), user: maskUser(username), pwLen: String(password).length });
      // ack is empty and confirmation happens in the native prompt, so a slow ack is not an error
      try {
        await this._send(Command.SET_PASSWORD_FOR_LOGIN_NAME_URL, body, 3000);
        this._logEvent("save.acked", "info", { host: hostParam(hostname), user: maskUser(username) });
      } catch (e) {
        this._logEvent("save.ack", "warn", { err: errInfo(e), tolerated: /timeout/i.test(String(e?.message ?? "")) });
        if (!/timeout/i.test(String(e?.message ?? e))) throw e;
      }
      return true;
    });
  }

  async getOneTimeCodes(tabId, frameId, frameUrls, username) {
    if (!this.ready) throw new Error("not unlocked");
    if (!this.canFillOneTimeCodes) return { entries: [], requiresAuth: false };
    const body = { ACT: Action.GHOST_SEARCH, TYPE: "oneTimeCodes", frameURLs: frameUrls };
    if (username) body.username = username;
    return this._withLock(async () => {
      const res = await this._encryptedQuery(Command.GET_ONE_TIME_CODES, tabId, null, body, 8000, frameId);
      const requiresAuth = !!res.RequiresUserAuthenticationToFill;
      this._logEvent("query", res.STATUS === QueryStatus.Success ? "debug" : "warn", {
        cmd: QueryId[Command.GET_ONE_TIME_CODES],
        status: res.STATUS,
        n: (res.Entries ?? []).length,
        requiresAuth,
        urls: (frameUrls || []).map((u) => safeUrl(u)),
        tab: tabId,
        frame: frameId,
      });
      if (res.STATUS === QueryStatus.Success) return { entries: normalizeOtpEntries(res.Entries), requiresAuth };
      if (res.STATUS === QueryStatus.NoResults) return { entries: [], requiresAuth };
      throw queryStatusError(res.STATUS);
    });
  }

  // read at pick time so a code listed earlier isnt filled after it rotated. no timeout, may need Touch ID
  async readOneTimeCode(tabId, frameId, frameUrls, username) {
    if (!this.ready) throw new Error("not unlocked");
    const body = { ACT: Action.SEARCH, TYPE: "oneTimeCodes", frameURLs: frameUrls };
    if (username) body.username = username;
    return this._withLock(async () => {
      const res = await this._encryptedQuery(Command.DID_FILL_ONE_TIME_CODE, tabId, null, body, null, frameId);
      this._logEvent("query", res.STATUS === QueryStatus.Success ? "debug" : "warn", {
        cmd: QueryId[Command.DID_FILL_ONE_TIME_CODE],
        status: res.STATUS,
        n: (res.Entries ?? []).length,
        user: maskUser(username),
        tab: tabId,
        frame: frameId,
      });
      if (res.STATUS === QueryStatus.Success) return normalizeOtpEntries(res.Entries);
      if (res.STATUS === QueryStatus.NoResults) return [];
      throw queryStatusError(res.STATUS);
    });
  }

  launchPasswordsApp({ searchUrl, newPasswordUrl, totpUri, totpPageUrl } = {}) {
    if (!this.port) throw new Error("not connected");
    const msg = { cmd: Command.LAUNCH_PASSWORDS_APP };
    // the otpauth URI carries the TOTP secret, only its shape goes into the log
    this._logEvent("app.launch", "info", {
      mode: totpUri ? "totp" : newPasswordUrl ? "new" : "search",
      hasUri: !!totpUri,
      uriScheme: totpUri ? String(totpUri).split(":")[0].slice(0, 20) : undefined,
      target: searchUrl || newPasswordUrl ? safeUrl(searchUrl || newPasswordUrl) : undefined,
    });
    if (totpUri) {
      if (!this.canSetUpTotp) throw new Error("this helper cant set up verification codes");
      msg.setUpTOTPURI = totpUri;
      if (totpPageUrl) msg.setUpTOTPPageURL = totpPageUrl;
    } else if (newPasswordUrl) {
      if (!this.canOpenPasswordsAppToNewPasswordSheet) throw new Error("this helper cant open the new-password sheet");
      msg.newPasswordWithSuggestedURL = newPasswordUrl;
    } else if (searchUrl) {
      msg.searchQueryURL = searchUrl;
    }
    this.port.postMessage(msg);
  }

  disconnect() {
    if (!this.port) return;
    this._logEvent("disconnect", "info", { by: "user" });
    try {
      this.port.postMessage({ cmd: Command.END });
    } catch (_) {}
    try {
      this.port.disconnect();
    } catch (_) {}
    this.port = undefined;
    this.session = undefined;
    this._setState(State.Disconnected, "user disconnected");
  }
}
