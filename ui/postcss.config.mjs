/**
 * Tailwind v4 runs as a PostCSS plugin and nothing else.
 *
 * Worth stating because of the constraint the rest of this app is built
 * around: `build.rs` embeds `ui/out` into every `cairn` binary, and an
 * operator often reads the result over an SSH tunnel on a box with no route
 * out. Tailwind is a *build-time* dependency — it compiles `globals.css` into
 * one static stylesheet and ships no runtime, no font, and no request. The
 * play-CDN build (`cdn.tailwindcss.com`) would break both properties at once
 * and must never appear here.
 */
const config = {
  plugins: {
    "@tailwindcss/postcss": {},
  },
};

export default config;
