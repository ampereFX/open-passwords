// Runs in the extension iframe that the dropdown shows while the vault is locked. It
// talks to the worker directly; the content script only learns "ready" and, through
// the worker's "unlocked" push, that the code was accepted. The code never touches
// the page or the content script.

const nonce = location.hash.slice(1);
const input = document.getElementById("pin");
const status = document.getElementById("status");
const again = document.getElementById("again");

function send(msg) {
  return chrome.runtime.sendMessage(msg).catch((e) => ({ ok: false, error: String(e?.message ?? e) }));
}

function setStatus(text, isError) {
  status.textContent = text;
  status.classList.toggle("err", !!isError);
}

let verifying = false;
async function verify() {
  if (verifying) return;
  const pin = input.value.trim();
  if (pin.length < 4) return;
  verifying = true;
  setStatus("Verifying...", false);
  const res = await send({ type: "verifyPin", pin, viaPinFrame: true });
  verifying = false;
  if (res?.ok && res.state === "unlocked") {
    // the worker tells the tab, the content script then replaces this box
    setStatus("Unlocked", false);
    return;
  }
  // a failed attempt spends the code, the worker already put a new one on the Mac
  const base = res?.error || "Verification failed";
  setStatus(res?.newCode ? `${base} - enter the new code on your Mac` : base, true);
  input.value = "";
  input.focus();
}

input.addEventListener("keydown", (e) => {
  if (e.key === "Enter") verify();
  if (e.key === "Escape") send({ type: "pinFrameClose", nonce });
});
input.addEventListener("input", () => {
  if (input.value.trim().length === 6) verify();
});

again.addEventListener("click", async () => {
  input.value = "";
  setStatus("Asking your Mac for a new code...", false);
  const r = await send({ type: "requestChallenge" });
  setStatus(r?.ok ? "Enter the new code on your Mac" : r?.error || "Couldn't request a code", !r?.ok);
  input.focus();
});

addEventListener("focus", () => input.focus());
input.focus();
send({ type: "pinFrameReady", nonce });
