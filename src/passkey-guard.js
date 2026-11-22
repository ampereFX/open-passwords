// with the toggle on, swallow conditional passkey autofill. modal sign-in and password requests pass through
(() => {
  const creds = navigator.credentials;
  if (!creds || typeof creds.get !== "function") return;

  const orig = creds.get.bind(creds);
  // unknown until the isolated-world bridge has read the setting. Pages that ask for
  // conditional passkeys right at load used to get through before it arrived.
  let hide = null;
  const held = new Set();

  const release = () => {
    for (const h of [...held]) {
      held.delete(h);
      orig(h.options).then(h.resolve, h.reject);
    }
  };
  const set = (v) => {
    hide = v;
    // turning the toggle off (or learning it was off) hands held requests to the browser
    if (!hide) release();
  };
  addEventListener("openpasswords:hide-passkeys-on", () => set(true));
  addEventListener("openpasswords:hide-passkeys-off", () => set(false));
  // never hold a page hostage if the bridge does not answer (storage unavailable)
  setTimeout(() => {
    if (hide === null) set(false);
  }, 1500);

  creds.get = function (options) {
    const conditional = !!(options && options.mediation === "conditional" && options.publicKey);
    if (!conditional || hide === false) return orig(options);
    // hidden, or not known yet: keep it pending, honour abort so the page can clean up
    return new Promise((resolve, reject) => {
      const h = { options, resolve, reject };
      const sig = options.signal;
      if (sig?.aborted) return reject(new DOMException("Aborted", "AbortError"));
      held.add(h);
      sig?.addEventListener(
        "abort",
        () => {
          if (held.delete(h)) reject(new DOMException("Aborted", "AbortError"));
        },
        { once: true },
      );
    });
  };
})();
