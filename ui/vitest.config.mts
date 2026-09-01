import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Tests for `lib/*.ts` only. Everything under test is a pure function over
// what a node answered -- no DOM, no React, no fetch -- so the default `node`
// environment is enough and jsdom is deliberately not a dependency: the pages
// are exercised by `next build` and by `scripts/node-smoke.sh` against a real
// node, and a component test that mocked the node would test the mock.
//
// The one thing this file has to say is the `@/` alias, which `tsconfig.json`
// declares for `tsc` and Next and vitest does not read on its own.
export default defineConfig({
  resolve: {
    alias: { "@": fileURLToPath(new URL(".", import.meta.url)) },
  },
  test: {
    include: ["lib/**/*.test.ts"],
    environment: "node",
  },
});
