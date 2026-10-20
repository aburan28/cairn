export type SetupGuide = {
  summary: string;
  description: string;
  commands: Array<{ label: string; text: string }>;
  footer: string;
};

const PUBLIC: SetupGuide = {
  summary: "Start with local work. Sharing with other computers is optional; use advanced setup when you want to connect them.",
  description: "Four commands over Tailscale: HTTPS on your tailnet, the open internet behind a funnel, and peers that dial the p2p port directly. Result — https://<your-magicdns-name>:8443 for this reader and the API, your Tailscale IP and port 9000 for other nodes.",
  commands: [
    { label: "1 · run the node (p2p on the wildcard, HTTP on loopback)", text: "cairn run --listen 0.0.0.0:9000 --serve 127.0.0.1:8080" },
    { label: "2 · sign in once", text: "tailscale up" },
    { label: "3 · HTTPS for the tailnet", text: "tailscale serve --bg --https=8443 http://127.0.0.1:8080" },
    { label: "4 · and for the open internet", text: "tailscale funnel --https=8443 --bg http://127.0.0.1:8080" },
  ],
  footer: "Verify the public half with tailscale funnel status. Always use the --https= flag plus the full backend URL — a bare port number is read as the target and can clobber other routes. The full recipe, including what peers need, is docs/publishing.md in the repository.",
};

const PRIVATE: SetupGuide = {
  summary: "This is a private installation. Keep it on your approved network and ask your administrator to connect other computers.",
  description: "This is a private installation. Restore the existing internal or WireGuard connection with your network administrator. Use this node’s assigned internal address; 10.80.0.1 below is an example, and must already exist on its interface.",
  commands: [
    { label: "1 · start the leader on its configured private interface", text: "CAIRN_NETWORK=private cairn run --no-mcp --serve 10.80.0.1:8080" },
    { label: "2 · check its internal endpoint from the worker", text: "curl --fail http://10.80.0.1:8080/health" },
  ],
  footer: "Check internal routes, firewall permissions and DNS with your administrator. Keep WireGuard private keys on their owning machines and enroll workers with the leader’s fleet invitation. Replicating nodes need explicit bootstrap peers. Network access does not grant application permissions. Setup details are in docs/fleet.md, under Private installations and WireGuard.",
};

/** Only the exact marker injected by the serving node selects private guidance. */
export function networkSetup(profile: string | null | undefined): SetupGuide {
  return profile === "private" ? PRIVATE : PUBLIC;
}
