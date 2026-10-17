import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Data transformations use Node. The small component lifecycle suite opts into
// jsdom per file; real packaged-reader/network acceptance remains a separate
// browser command rather than a mocked service in the default unit suite.
//
// Match the `@/` alias declared for TypeScript and Next; Vitest does not read
// that mapping on its own.
export default defineConfig({
  oxc: { jsx: { runtime: "automatic" } },
  resolve: {
    alias: { "@": fileURLToPath(new URL(".", import.meta.url)) },
  },
  test: {
    include: ["lib/**/*.test.ts", "components/**/*.test.tsx"],
    environment: "node",
    environmentOptions: { jsdom: { url: "http://localhost/" } },
  },
});
