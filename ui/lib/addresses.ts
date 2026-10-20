/** Presentation only: a bind address is not an address another node can use. */
export function endpointKind(value: string | null | undefined): "address" | "local" | "unspecified" | "unknown" {
  if (!value?.trim()) return "unknown";
  try {
    const text = value.trim();
    const bareIPv6 = !text.includes("://") && !text.startsWith("[") && text.split(":").length > 2;
    const url = new URL(text.includes("://") ? text : `http://${bareIPv6 ? `[${text}]` : text}`);
    if (url.username || url.password || !["http:", "https:", "tcp:"].includes(url.protocol)) return "unknown";
    const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
    if (host === "0.0.0.0" || host === "::" || host === "::ffff:0:0") return "unspecified";
    if (host === "localhost" || host.endsWith(".localhost") || host === "::1" || /^127(?:\.[0-9]+){3}$/.test(host) || /^::ffff:7f[0-9a-f]{2}:[0-9a-f]+$/.test(host)) return "local";
    return "address";
  } catch {
    return "unknown";
  }
}

/** Keep real peer IPs/hostnames intact. Raw local/bind endpoints belong in Diagnostics. */
export function peerAddress(value: string | null | undefined): string {
  const kind = endpointKind(value);
  if (kind === "local") return "Local connection";
  if (kind !== "address") return "Not advertised";
  const text = value!.trim();
  return text.includes("://") ? new URL(text).host : text;
}
