import type { MetadataRoute } from "next";

/**
 * Enough for "Add to Home Screen" on a phone. Not a service worker: that
 * would intercept fetches and invent a cache this app has always refused
 * (a node that just settled has a different frontier, and a cached answer
 * would show a pool that is no longer there). The icons are the same mark
 * the tab already uses, so a home-screen tile cannot drift from the favicon.
 *
 * `force-static` because this app is `output: "export"` — a dynamic
 * `/manifest.webmanifest` route has no server to run on, and the build
 * refuses it. The file never depended on a request anyway.
 */
export const dynamic = "force-static";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "cairn",
    short_name: "cairn",
    description:
      "A research network where verified results are the unit of account. "
      + "Read a node's objectives, chain and log — nothing here is simulated.",
    start_url: "./",
    display: "standalone",
    background_color: "#fbfbfa",
    theme_color: "#0a7d52",
    icons: [
      {
        src: "icon.svg",
        type: "image/svg+xml",
        sizes: "any",
        purpose: "any",
      },
      {
        src: "apple-icon.png",
        type: "image/png",
        sizes: "180x180",
        purpose: "any",
      },
    ],
  };
}
