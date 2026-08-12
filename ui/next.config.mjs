/** @type {import('next').NextConfig} */
// No `output: "export"`. The whole point of this app is to read a *live* node,
// so a static export with the chain baked in at build time would be a snapshot
// pretending to be a reader.
const nextConfig = { reactStrictMode: true };
export default nextConfig;
