/** @type {import('next').NextConfig} */
// `output: "export"`, and the objection this comment used to raise does not
// apply to the app that is actually here.
//
// It said a static export "would be a snapshot pretending to be a reader",
// which is true of a *server* component that fetches at build time and bakes
// the answer into HTML. Every page here is `"use client"` and fetches in
// `useEffect` against a URL the page itself lets you edit — so the export
// contains no chain, no head, and no objective. It is the reader, shipped as
// files instead of as a Node process.
//
// That is what lets the daemon serve it: `build.rs` embeds this directory in
// the binary behind the `ui` feature, and `cairn-p2p --serve` answers it
// at /ui/. An operator reading their own node's chain should not have to
// install a Node toolchain to do it.
//
// `basePath` is where this build will be mounted, and there are two answers.
// Embedded in the node binary it lives under /ui/, because / is the endpoint
// index — a different and smaller job. Deployed to GitHub Pages it lives under
// the repository name, or at the root behind a custom domain. Neither is more
// correct, so it comes from the environment and defaults to the embedded case,
// which is the one `make ui-build` and the release workflow perform.
//
// `trailingSlash` so /ui/peers resolves to peers/index.html without a rewrite
// engine; the server here is a few hundred lines and has none.
// `images.unoptimized` because the optimizer is a server, and there is none.
const basePath = process.env.NEXT_BASE_PATH ?? "/ui";

const nextConfig = {
  reactStrictMode: true,
  output: "export",
  basePath,
  trailingSlash: true,
  images: { unoptimized: true },
};
export default nextConfig;
