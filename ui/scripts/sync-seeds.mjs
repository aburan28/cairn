/**
 * Copy the seed list into the static export, so GitHub Pages serves it.
 *
 * # Why a copy step and not a committed second file
 *
 * `launch/seeds.json` is the source, and it is the *only* source. `ui/` is a
 * Next app whose static assets have to live under `ui/public/`, so publishing
 * the list means the bytes exist in two places at build time — and the one
 * thing that must not happen is for both to be committed, drift, and leave two
 * answers to "which seeds does this project publish". So the copy is generated
 * on every `npm run build` and `npm run dev`, and `ui/public/` is gitignored.
 *
 * The same reasoning as `ui/lib/snapshot.json` reaching the opposite
 * conclusion, and worth saying why. That file is committed because deriving it
 * needs a Rust build and a running node, so requiring one to build the site
 * would put a toolchain between a contributor and a typo fix; CI re-derives it
 * and fails on a mismatch. This is a file copy. There is nothing to re-derive
 * and nothing a checker would be checking.
 *
 * # What ends up published
 *
 * `seeds.json` at the site root, and `seeds/<transport>.key` beside it — the
 * layout `scripts/seeds-fetch.sh` and `cairn seeds resolve` expect, so the
 * published site and a local checkout are the same tree and a `file://` copy of
 * one works as a seed source for the other.
 */
import { cp, mkdir, rm, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..");
const publicDir = join(here, "..", "public");

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

const list = join(repo, "launch", "seeds.json");
if (!(await exists(list))) {
  // Not a build failure. A fork may carry no seed list at all, and a site
  // without one degrades to exactly what it did before this existed: the node
  // URL box, and the bundled log behind it.
  console.warn("sync-seeds: no launch/seeds.json; the site will publish no seed list");
  process.exit(0);
}

// Removed rather than merged. A key file for a seed that was withdrawn from the
// list must not survive in an old export and go on being served.
await rm(join(publicDir, "seeds.json"), { force: true });
await rm(join(publicDir, "seeds"), { recursive: true, force: true });
await mkdir(publicDir, { recursive: true });

await cp(list, join(publicDir, "seeds.json"));
const keys = join(repo, "launch", "seeds");
if (await exists(keys)) {
  await cp(keys, join(publicDir, "seeds"), { recursive: true });
}
console.log("sync-seeds: published launch/seeds.json to ui/public/");
