// Which origins may receive a fill over plain HTTP.
//
// A public http:// page must never get a vault password: that is the case this guard
// exists for. Local-network addresses are different — routers, NAS boxes, Pi-holes and
// dev servers routinely have no HTTPS at all, and a fill there still needs an explicit
// click on a row. Keeping this in its own module makes the matrix testable.

export function isLocalNetworkHost(host) {
  if (!host) return false;
  const h = String(host).toLowerCase();

  if (h === "localhost" || h === "127.0.0.1" || h === "[::1]" || h === "::1") return true;

  // RFC 6761/8375 style names that only resolve locally
  if (
    h.endsWith(".localhost") ||
    h.endsWith(".test") ||
    h.endsWith(".local") ||
    h.endsWith(".lan") ||
    h.endsWith(".home.arpa") ||
    h.endsWith(".internal")
  ) {
    return true;
  }

  // private IPv4 (RFC 1918), link-local (APIPA), loopback
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a > 255 || b > 255) return false;
    return (
      a === 10 || // 10/8
      a === 127 || // loopback
      (a === 172 && b >= 16 && b <= 31) || // 172.16/12
      (a === 192 && b === 168) || // 192.168/16
      (a === 169 && b === 254) // 169.254/16
    );
  }

  // IPv6 unique-local / link-local, as URL.hostname reports them
  if (/^\[(fc|fd|fe80)/i.test(h)) return true;

  // a single-label name (http://nas/, http://router/) only resolves through local DNS
  if (!h.includes(".") && h !== "") return true;

  return false;
}

/**
 * "https" | "http-local" | "http-public".
 * The caller may fill on the first two, never on the third.
 */
export function schemeClass(url, host) {
  if (/^https:/i.test(String(url || ""))) return "https";
  return isLocalNetworkHost(host) ? "http-local" : "http-public";
}
