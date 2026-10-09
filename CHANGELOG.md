# Changelog

## [3.0.0](https://github.com/aburan28/cairn/compare/v2.2.2...v3.0.0) (2026-10-09)


### ⚠ BREAKING CHANGES

* rename proofwork to cairn

### Features

* add make ui target and ecdsa-fail live objective ([3298c7e](https://github.com/aburan28/cairn/commit/3298c7e7c95bcf68fd1f24886f74608cdb88e09e))
* add make ui target and ecdsa-fail live objective ([aa8ad16](https://github.com/aburan28/cairn/commit/aa8ad16bba1761b48697c617f97ff4bf24777c0f))
* **agent:** the host agent -- hardware registration and gVisor/Kata executor jobs under systemd ([d22f080](https://github.com/aburan28/cairn/commit/d22f0807f606ab0d270141e1a952be8be1df5fc1))
* **agent:** the host agent -- hardware registration and gVisor/Kata executor jobs under systemd ([879185e](https://github.com/aburan28/cairn/commit/879185e8179b9e24026a2555474c803b39f5dae6))
* an epoch beacon a sequencer cannot grind ([04f027d](https://github.com/aburan28/cairn/commit/04f027d41cec1334f7a7b6391a33032e1e904d9d))
* an objective pinning alloc-init's published AADP challenge ([5f62d32](https://github.com/aburan28/cairn/commit/5f62d320d2640ee3a2cfd65f565ab0136d81efbe))
* an objective pinning alloc-init's published AADP challenge ([9a56609](https://github.com/aburan28/cairn/commit/9a56609adee7b182e168d44fb528c57e71a04f07))
* **app:** every Contribute role is a button in Cairn.app, and peers say what they offer ([#249](https://github.com/aburan28/cairn/issues/249)) ([b93dd9a](https://github.com/aburan28/cairn/commit/b93dd9aa7d2840e46b7b7136afb8fc7c1fec3b6a))
* **attest:** the validator loop, knowledge over HTTP, and the first replay example ([#228](https://github.com/aburan28/cairn/issues/228)) ([9bb6daf](https://github.com/aburan28/cairn/commit/9bb6daf08dcc324dc5e056c6bf839fadadbe4fba))
* cairn secret, and an ECC2K-130 DP upload/ingest seam ([#173](https://github.com/aburan28/cairn/issues/173)) ([9cb9657](https://github.com/aburan28/cairn/commit/9cb96579eba3446cbd451ecd67edb5f8a758d7a5))
* citation-flow harness as a CLI, and a CSV export that exports ([#142](https://github.com/aburan28/cairn/issues/142)) ([0e22188](https://github.com/aburan28/cairn/commit/0e22188d7907694ee2d8996f3e598340846ddd1e))
* **cli:** sign live objectives and expose public claims ([d78ef48](https://github.com/aburan28/cairn/commit/d78ef48f63c724d217a4a0ecb2ec4283631484d3))
* crypto autoresearcher end to end over MCP, plus a macOS launcher ([#130](https://github.com/aburan28/cairn/issues/130)) ([f10685d](https://github.com/aburan28/cairn/commit/f10685dbcea3219504b8825aa3e6f87dba627e57))
* deposit grants for mediated cloud uploads ([#174](https://github.com/aburan28/cairn/issues/174)) ([7d289dd](https://github.com/aburan28/cairn/commit/7d289dd405bec7cfa1c1a5e10266106bbae2f5a4))
* **deposit:** campaign key shape with commit markers, upload through grants ([#262](https://github.com/aburan28/cairn/issues/262)) ([60ffa67](https://github.com/aburan28/cairn/commit/60ffa67f755530f68a574969cc5f1180bb3586d7))
* **ecc2k:** CPU end-to-end — walk, strip, verify-local, witness ([dd52bff](https://github.com/aburan28/cairn/commit/dd52bffa85d94c53ec9a6295004da5d54eca476b))
* ECDLP objectives -- Certicom's frontier, and a ladder you can climb ([67f4a1a](https://github.com/aburan28/cairn/commit/67f4a1a85d6791b23e52a9da4a273e9348f28592))
* ECDLP objectives — Certicom's frontier, and a ladder you can climb ([ca99a2e](https://github.com/aburan28/cairn/commit/ca99a2eb1b99440d8576b786820633338b0e3265))
* erasure-coded shards, with a Merkle commitment per chunk ([ace2e4c](https://github.com/aburan28/cairn/commit/ace2e4c0fe29e05f46ac9597ba4b2460509a4056))
* erasure-coded shards, with a Merkle commitment per chunk ([c0dee58](https://github.com/aburan28/cairn/commit/c0dee5896573c92128dc09d77313e430fb1a9e25))
* **examples:** differential-path bounties for MD4, MD5, SHA-0 and SHA-1 ([#127](https://github.com/aburan28/cairn/issues/127)) ([08979b5](https://github.com/aburan28/cairn/commit/08979b5621c61297e2ba10a791fd2363fc1b0a49))
* **fleet:** a leader that signs and is paid, workers on your own network, a private peer allowlist, Linux units, and the Mac node as an opt-in launchd agent ([9d82f66](https://github.com/aburan28/cairn/commit/9d82f66877109f76bfe6f0ec45e1890448ea987b))
* **fleet:** a leader that signs and is paid, workers on your own network, a private peer allowlist, Linux units, and the Mac node as an opt-in launchd agent ([809e659](https://github.com/aburan28/cairn/commit/809e659d3d8c917d4bc1d76c1ecb081514ecfa57))
* **fleet:** members enrolled from anywhere, reasons on every submission, underserved angles, and a payouts design ([ff568de](https://github.com/aburan28/cairn/commit/ff568de06495709e731583d0aefb1d73b2faa78a))
* **goals:** goals and angles -- one problem, many approaches -- read off the goal handle, with a catalog that joins two spellings, find_goal before posting, a Goals page, and dictation in New Challenge ([#230](https://github.com/aburan28/cairn/issues/230)) ([3921d18](https://github.com/aburan28/cairn/commit/3921d18d4fe7fbd403c7017fb4fd6c53be2857b4))
* **gui:** discover the models each AI provider serves in Settings → AI ([#212](https://github.com/aburan28/cairn/issues/212)) ([51defca](https://github.com/aburan28/cairn/commit/51defca97bcf04bd34409d87dd9598a960c0f28b))
* install the release binaries without a toolchain ([916d7fd](https://github.com/aburan28/cairn/commit/916d7fd7b5697983d1d64d0b7b264727152cdb9f))
* install the release binaries without a toolchain ([0f1481a](https://github.com/aburan28/cairn/commit/0f1481a59572f28d97f9c65f5a21676a91dee2ed))
* install with curl, and one process instead of three ([c31b4ee](https://github.com/aburan28/cairn/commit/c31b4eee7bf0bd47b670c76ae5a7bdbad76a0c1f))
* **ios:** a Task progress screen, from the node's /progress route ([#222](https://github.com/aburan28/cairn/issues/222)) ([f6332cd](https://github.com/aburan28/cairn/commit/f6332cd4fcbdb03f780e5982746917a49a53eec1))
* **ios:** frontier history, and stop a late log fetch undoing fallback ([#157](https://github.com/aburan28/cairn/issues/157)) ([e5ce3e9](https://github.com/aburan28/cairn/commit/e5ce3e9cb17ac3ea93041c611f3e533640272219))
* **lab:** a replicated research workspace — signed op CRDT, sync, and gVisor runs ([3e44934](https://github.com/aburan28/cairn/commit/3e4493445311cc0a08d95567dc5c3ecdee35e5a8))
* **lab:** lab-demo.sh, honest exit codes, and a forced checkout that restores ([59bc69d](https://github.com/aburan28/cairn/commit/59bc69ddb8fc6b909149a5372f034a13facf40ea))
* **macos:** a real app icon for Cairn.app ([#203](https://github.com/aburan28/cairn/issues/203)) ([2beee5f](https://github.com/aburan28/cairn/commit/2beee5fe22dbb76d47125cdeeef5f1c241d7843a))
* **macos:** AI-drafted challenges, Tasks without a checkout, and a connectivity test ([#200](https://github.com/aburan28/cairn/issues/200)) ([8981801](https://github.com/aburan28/cairn/commit/8981801475be4baf0439bb5064520472a41f9632))
* **macos:** announce peers, attach to a URL, and reader-side checks ([ac17fd8](https://github.com/aburan28/cairn/commit/ac17fd8f0fd6b570ac83dd66b0619b87ff4244dc))
* **macos:** announce peers, attach to a URL, and reader-side checks ([1c43da2](https://github.com/aburan28/cairn/commit/1c43da2653ed6198c630ef5d7f38607c203f8f09))
* **macos:** check for updates in Cairn.app and show its version ([#197](https://github.com/aburan28/cairn/issues/197)) ([d342181](https://github.com/aburan28/cairn/commit/d34218181400ed44fc65933b45ce1da51fd2fd59))
* **macos:** Check for Updates in Cairn.app, and show versions ([#196](https://github.com/aburan28/cairn/issues/196)) ([785b534](https://github.com/aburan28/cairn/commit/785b534ff4510aad0fda1e1b378df4e2393cc15b))
* **macos:** drafted challenges are Lean theorems, with real progress and the toolchain found ([08930a9](https://github.com/aburan28/cairn/commit/08930a9b912e67b8ff8066c4e998e20d7d52866f))
* **macos:** Lean-only drafting with streamed progress, the toolchain found and handed to the node, and Connect an Agent ([bf48468](https://github.com/aburan28/cairn/commit/bf48468f30d964c8b2d076b4aae8298ff12b55ed))
* **macos:** Lean-only drafting with streamed progress, the toolchain found and handed to the node, and Connect an Agent ([#224](https://github.com/aburan28/cairn/issues/224)) ([bf48468](https://github.com/aburan28/cairn/commit/bf48468f30d964c8b2d076b4aae8298ff12b55ed))
* **macos:** limit what Cairn.app's node may use, and choose its data folder ([#164](https://github.com/aburan28/cairn/issues/164)) ([1715e4e](https://github.com/aburan28/cairn/commit/1715e4e57082dab3cf2216db1918c3db4b8c91ec))
* **macos:** make Cairn.app join the network, and harden the Autoresearcher ([a44c42f](https://github.com/aburan28/cairn/commit/a44c42fbf7c63f4bda127a25390a2662c9ca058f))
* **macos:** make Cairn.app join the network, and harden the Autoresearcher ([d100812](https://github.com/aburan28/cairn/commit/d10081236f10151e7632ff3cd33b1aab6d751a75))
* **macos:** Node → Connect an Agent…, the MCP stanza with this Mac's paths in it ([08fc9a9](https://github.com/aburan28/cairn/commit/08fc9a97caa706b428ced1be39b1494a8fc7877d))
* **macos:** paste named secrets in the GUI ([#179](https://github.com/aburan28/cairn/issues/179)) ([6a73cf9](https://github.com/aburan28/cairn/commit/6a73cf9134b81b1b963d011bf2d1fd04f32dee0f))
* **macos:** post-quantum (ML-DSA-87) signatures on Cairn.app updates ([#204](https://github.com/aburan28/cairn/issues/204)) ([4025336](https://github.com/aburan28/cairn/commit/4025336c064a816209871ed50671482ea0f3edac))
* **macos:** ship Cairn.app in the .dmg ([#162](https://github.com/aburan28/cairn/issues/162)) ([db1f17e](https://github.com/aburan28/cairn/commit/db1f17e45418b3a6439a054bddc05e4801abcb27))
* make the us-west seed real ([#139](https://github.com/aburan28/cairn/issues/139)) ([e182c7c](https://github.com/aburan28/cairn/commit/e182c7c116603270f378270a065db224d667d6ad))
* **mcp:** surface a claim's standing where an agent will actually see it ([51f0720](https://github.com/aburan28/cairn/commit/51f0720a0f0bf511dfb02af759347593f681f635))
* native iOS reader and a phone-installable site ([#155](https://github.com/aburan28/cairn/issues/155)) ([014c3e0](https://github.com/aburan28/cairn/commit/014c3e051f7ad9c99de991f7be6f0ecbfd9bfc3e))
* **network:** live sessions, the compute roster, advisory leases and declared roles, with Network and Coordination pages ([d8c935e](https://github.com/aburan28/cairn/commit/d8c935eed30b86a49e7e628bf384cebc7e57f31f))
* **network:** live sessions, the compute roster, advisory leases and declared roles, with Network and Coordination pages ([d6da24f](https://github.com/aburan28/cairn/commit/d6da24fb9143f2af41d996c9d40ce591a7d9ccda))
* one `cairn` binary — `run` serves MCP, the other binaries become subcommands, `make build` stages bin/ ([#128](https://github.com/aburan28/cairn/issues/128)) ([6897143](https://github.com/aburan28/cairn/commit/689714325b9f5e8b9f4300cc389160e29105b205))
* **p2p:** port mapping wired into the daemon -- NAT-PMP, then UPnP IGD -- reported as a claim beside the evidence, with a two-node runbook and a no-GitHub-links guard ([e00cc03](https://github.com/aburan28/cairn/commit/e00cc0309042dbe58434379e25fa1113e107baa7))
* **p2p:** port mapping wired into the daemon (NAT-PMP, then UPnP), reported as a claim beside the evidence; a two-node runbook; no reader links to github.com ([6d7d128](https://github.com/aburan28/cairn/commit/6d7d12861ef3907ffd5cbdbfaaad7c4ad225b6ac))
* **progress:** a per-task dashboard for a divided search, from the log and from worker heartbeats ([87e7e82](https://github.com/aburan28/cairn/commit/87e7e82ab70c2f3379496474c01d1f9e01807c3b))
* **progress:** a per-task dashboard for a divided search, from the log and from worker heartbeats ([335d68e](https://github.com/aburan28/cairn/commit/335d68e459b5f6f05aa8f100cca4cffc85c297dc))
* **progress:** point the autoresearcher GUI and the MCP tool at the task dashboard ([1d78056](https://github.com/aburan28/cairn/commit/1d780568e6f9342ed3e31de75d9b1c50761d4e4e))
* **progress:** point the autoresearcher GUI and the MCP tool at the task dashboard ([5706bd0](https://github.com/aburan28/cairn/commit/5706bd021dc48f0099da69837eb2b317554f4c51))
* publish seed node endpoints on GitHub Pages ([#137](https://github.com/aburan28/cairn/issues/137)) ([31eeb6c](https://github.com/aburan28/cairn/commit/31eeb6c36110c0b14059cbc311b2e959bb70f0e1))
* readable reader, LAN workers with `cairn work`, and roles priced honestly ([#231](https://github.com/aburan28/cairn/issues/231)) ([749de36](https://github.com/aburan28/cairn/commit/749de36a54f066e71fd35b28c16a12eb2c8c6493))
* **release:** ship a .dmg, a .deb and an .rpm ([#161](https://github.com/aburan28/cairn/issues/161)) ([1a16c45](https://github.com/aburan28/cairn/commit/1a16c4526df50566a1f64c95fea73cec9474cb9e))
* rename proofwork to cairn ([940e21a](https://github.com/aburan28/cairn/commit/940e21a943087b04009ce0b44463f91f26c6228c))
* **sealed:** committee shares are checkable on their own, and the reference decodes envelopes ([854307f](https://github.com/aburan28/cairn/commit/854307f90ea42f38d645d0c2e731756cc0f9c3a7))
* **sealed:** the dealer commits to its sharing and answers for every seat, in both implementations ([c47d947](https://github.com/aburan28/cairn/commit/c47d94717df8946f75204bd0e8f691ad6a401df8))
* **secret:** path, env remapping, and ECC2K status helpers ([#172](https://github.com/aburan28/cairn/issues/172)) ([bdcc552](https://github.com/aburan28/cairn/commit/bdcc552721ec4cae5412747b66385dea2a09db10))
* **serve:** optional Google sign-in, anonymous by default ([#245](https://github.com/aburan28/cairn/issues/245)) ([862ed71](https://github.com/aburan28/cairn/commit/862ed71ac183fcfdf084370e6afeed3259abff26))
* settle on the clock, not on arrival order ([7fbae4b](https://github.com/aburan28/cairn/commit/7fbae4bef1507540187dc1d8c8175777f9e60bc6))
* settle on the clock, not on arrival order (re-target to main) ([816efa1](https://github.com/aburan28/cairn/commit/816efa15b1153c7cc62d611cb1ba5a1a5146030a))
* **site:** publish to Pages, and add the two pages a visitor needs ([#95](https://github.com/aburan28/cairn/issues/95)) ([ff10af2](https://github.com/aburan28/cairn/commit/ff10af295069e45d80e944958f45981be36304ee))
* typed claim relations, and a knowledge view nobody has to agree with ([243333f](https://github.com/aburan28/cairn/commit/243333f1211aa1ec08441fe9904914a0f10550e8))
* typed claim relations, and a knowledge view nobody has to agree with ([eb23ea2](https://github.com/aburan28/cairn/commit/eb23ea23d4a3bcad367fc57b2c275c96bbd26c00))
* **ui:** a cairn site whose numbers are re-derivable ([acc6e39](https://github.com/aburan28/cairn/commit/acc6e39e3fc8d00eb41e3af1748e88a1b6acaf7b))
* **ui:** a records explorer and a frontier page ([#116](https://github.com/aburan28/cairn/issues/116)) ([17919cf](https://github.com/aburan28/cairn/commit/17919cf29151d015d6f2a2737d48d3f9025e3246))
* **ui:** app layout for the reader and Cairn.app ([#193](https://github.com/aburan28/cairn/issues/193)) ([90a7645](https://github.com/aburan28/cairn/commit/90a76458d04446aeda3772741fcf8db0df65d2bd))
* **ui:** green palette, voice challenge entry, and network topology ([#232](https://github.com/aburan28/cairn/issues/232)) ([d82a65c](https://github.com/aburan28/cairn/commit/d82a65c6d50c6e83305ab87df546c7e25b8af7a6))
* **ui:** post a challenge from a plain description in Cairn.app ([#206](https://github.com/aburan28/cairn/issues/206)) ([32f0d13](https://github.com/aburan28/cairn/commit/32f0d13442b64b562f0bb5a4ae9989492962794c))
* **ui:** redesigned reader, post challenges from the page, wallet-signed funding ([#131](https://github.com/aburan28/cairn/issues/131)) ([5fc3aee](https://github.com/aburan28/cairn/commit/5fc3aee0f3b86b63d117e12dc961358d73506e13))
* **ui:** show per-result knowledge evidence ([#263](https://github.com/aburan28/cairn/issues/263)) ([96e5936](https://github.com/aburan28/cairn/commit/96e593693d8dc29a0b718f750dea2bd317dc7f90))
* **ui:** your node's role, agents and events, coordinated tasks from a description, and verified results ([2557992](https://github.com/aburan28/cairn/commit/255799231fb95081f4a6bff6c14086007465bfa0))
* **vdf:** the reference checks delay proofs, and a reader can demand more delay than the floor ([919be6c](https://github.com/aburan28/cairn/commit/919be6c2bbb4a3d1a56d42119dd6a62cd7bf7934))
* **verifiers:** GET /verifiers, a Lean control run, and CAIRN_LEAN / CAIRN_LEAN_ROOT ([a166899](https://github.com/aburan28/cairn/commit/a1668994a9bb95fc30a327a07785298c288a6ddd))
* **verifiers:** workspace kind in both implementations ([#187](https://github.com/aburan28/cairn/issues/187)) ([43cac5c](https://github.com/aburan28/cairn/commit/43cac5c52f7834b51af56968b5605f8bb85c435b))


### Fixes

* a retraction needs the target's key, not a matching name ([ec66fee](https://github.com/aburan28/cairn/commit/ec66fee330ed125c1e95512e2cc2bb0dbc65de9c))
* a retraction needs the target's key, not a matching name ([8ef5751](https://github.com/aburan28/cairn/commit/8ef575113808a4d54d25e370543d23934c64d877))
* **agent,mcp:** no engine options through a job's image, the operator's sandbox is a floor, bounded node answers, create-only MCP secrets ([6cff3a3](https://github.com/aburan28/cairn/commit/6cff3a3df684d9f70018152c33582f17cda567ab))
* **canonical:** parse JSON in linear time; one path buffer, not a copy per element ([60740aa](https://github.com/aburan28/cairn/commit/60740aa98f18056d28697165049bc06949928125))
* **ci:** scripts/shard-demo.sh and mcp-config.sh lost their +x bit ([4b21d2f](https://github.com/aburan28/cairn/commit/4b21d2f3c1f8dacd7800216a66cfbf03b0051782))
* decode and canon without a log, like check already did ([#140](https://github.com/aburan28/cairn/issues/140)) ([8a9ec96](https://github.com/aburan28/cairn/commit/8a9ec960e8b3f688572f896fea99ff52bbfb088a))
* **deposit:** S3 uploads are bound to an exact length and checksum, and one address cannot hold every grant ([aabb199](https://github.com/aburan28/cairn/commit/aabb1999d1728c8a77ef7f8a5b0cacb3a562819e))
* **docs:** cargo doc -D warnings fails on main, independent of this branch ([26bb71d](https://github.com/aburan28/cairn/commit/26bb71d888b1d9037fa0f7cb8508b2a4c5c56d02))
* examples/ecdlp was a bounty whose author knew the answer ([f80b478](https://github.com/aburan28/cairn/commit/f80b478908ed06a8816c119db19bad614456c861))
* examples/ecdlp was a bounty whose author knew the answer ([906d2e9](https://github.com/aburan28/cairn/commit/906d2e9fbc8f3f0c91a11996817aad3ed4fd87a7))
* **gui:** Mac bootstrap launch bug and iOS App Store blockers ([84cf759](https://github.com/aburan28/cairn/commit/84cf759ac5e0a4f101c703287e237a75a9144dab))
* **gui:** restart without freezing Cairn.app; staple the installer pkg ([e7701dd](https://github.com/aburan28/cairn/commit/e7701dd559850cf01438908febbaaa404faa863b))
* **gui:** restart without freezing Cairn.app; staple the installer pkg ([490afd4](https://github.com/aburan28/cairn/commit/490afd4009166f5435f239effdb56b17ca165fcb))
* **gui:** unblock bootstrap launches on macOS, clear iOS App Store blockers ([c491681](https://github.com/aburan28/cairn/commit/c491681d352f563cc0c3d83e8117bcc39f81e609))
* **ios:** keep refresh writes on the generation that started them ([#158](https://github.com/aburan28/cairn/issues/158)) ([36bedf6](https://github.com/aburan28/cairn/commit/36bedf6db1603e25d74fc46a2df19579ae020933))
* **lab:** a run never writes into its environment; Sage and PARI environments ([2f0c5c1](https://github.com/aburan28/cairn/commit/2f0c5c1a14708e7c84637aa2573a94870c1065df))
* **launch:** publish the Runpod CPU seed ([9d94811](https://github.com/aburan28/cairn/commit/9d948116b8d0eb4f8bb141183fe38818dcfa1ab2))
* **macos:** compile drafted Lean in the node's jail; open only clicked web links; keep SSE blank lines ([856e2be](https://github.com/aburan28/cairn/commit/856e2bed88d5f45a3a15935e73ee0088e0da2b24))
* **macos:** let the Settings window scroll instead of running off screen ([#201](https://github.com/aburan28/cairn/issues/201)) ([90b5eda](https://github.com/aburan28/cairn/commit/90b5edac18c946b891b3da98832b8d58026af8aa))
* **mcp:** agents fund objectives only within the operator's ceiling, and take the network only with leave ([58da5e4](https://github.com/aburan28/cairn/commit/58da5e471b60f1e72ead1d81911ea6a925a76366))
* measure a log's epoch length instead of guessing at it ([d40b139](https://github.com/aburan28/cairn/commit/d40b1392ab9b15513d6910166e25af31d29af8bc))
* measure a log's epoch length instead of guessing at it ([159eb39](https://github.com/aburan28/cairn/commit/159eb398297d30ac275e5e0551308479575e10ca))
* omit structuredContent when there are no citations to carry ([#141](https://github.com/aburan28/cairn/issues/141)) ([926e608](https://github.com/aburan28/cairn/commit/926e608c396231e9aebafefa845400330634a1ed))
* **ops:** hardened units, a Pages build that cannot publish, signing secrets behind an environment, a drand fetch one relay cannot stop ([99bc5bb](https://github.com/aburan28/cairn/commit/99bc5bba5f2387b8de971a603c692231a50bb88f))
* **p2p:** dial the published seeds by default, and say when one is down ([24b9e5c](https://github.com/aburan28/cairn/commit/24b9e5c9b708d62dbfcf880530e02810230a210f))
* **p2p:** dial the published seeds by default, and say when one is down ([3b01df0](https://github.com/aburan28/cairn/commit/3b01df00b2c5df1219ce4ab4aae13ff40ce7d11f))
* **progress:** distinguish unavailable checks from rejections ([fdb6e09](https://github.com/aburan28/cairn/commit/fdb6e091b0ac99edc99d02fa8d7ea793ca8155ba))
* proxied requests are not fleet members, UPnP stays on the host that answered, secrets stay off argv, runs cannot fill the disk, leases have a ceiling ([359f9db](https://github.com/aburan28/cairn/commit/359f9db4bf64f56f34be4b48bb6cae51c11fd7a2))
* public-coin seeds are evidence, not branding ([3c121ce](https://github.com/aburan28/cairn/commit/3c121ce59769aa1da5fe0b0bdee3c9b3979528ea))
* public-coin seeds are evidence, not branding ([586d166](https://github.com/aburan28/cairn/commit/586d166da800a27e19f54795c1c2449b2b9478f2))
* **reference:** rustfmt the drift blocking [#116](https://github.com/aburan28/cairn/issues/116)'s reference job ([#118](https://github.com/aburan28/cairn/issues/118)) ([2aa56e8](https://github.com/aburan28/cairn/commit/2aa56e82ba3282414400b0fab92b055d89fe5d2b))
* refuse to settle a log under a changed epoch length ([4aa2148](https://github.com/aburan28/cairn/commit/4aa214819f43f1d4cf8da64f1fd73f2ef320d8bb))
* refuse to settle a log under a changed epoch length ([7cf0df4](https://github.com/aburan28/cairn/commit/7cf0df41682b489a5fea7982c4d1daebc9c3eb97))
* **release:** a release becomes latest only once it is complete ([96b7895](https://github.com/aburan28/cairn/commit/96b789559453c57857824e6f5cd0bd33a0012f11))
* **release:** a release becomes latest only once it is complete ([ec6cc2b](https://github.com/aburan28/cairn/commit/ec6cc2b6adff6a4040b0853ae7835f8e9331c604))
* **release:** build on tag creation, not only tag push ([#135](https://github.com/aburan28/cairn/issues/135)) ([9fe6f5e](https://github.com/aburan28/cairn/commit/9fe6f5edd0eb339ed0dfe12fb898355a48fda89e))
* **release:** create releases as drafts; publish as prereleases before building ([#221](https://github.com/aburan28/cairn/issues/221)) ([8d20043](https://github.com/aburan28/cairn/commit/8d20043801a99e9dcddc316d2dc6fab3f0264092))
* **release:** scope write tokens per job, pin third-party actions, protect published assets and the feed ([8b7ebd8](https://github.com/aburan28/cairn/commit/8b7ebd829b0c9e254b1cfc8f0b1f10cddb3367cd))
* **release:** start the build when release-please cuts a tag ([1a16c45](https://github.com/aburan28/cairn/commit/1a16c4526df50566a1f64c95fea73cec9474cb9e))
* **release:** stop the build erasing the changelog from the release page ([1a16c45](https://github.com/aburan28/cairn/commit/1a16c4526df50566a1f64c95fea73cec9474cb9e))
* **release:** upload assets with gh release upload, not a release PATCH ([96abb54](https://github.com/aburan28/cairn/commit/96abb543f2c3b2f0fe982f23b961406f8fa82dd7))
* **release:** upload assets with gh release upload, not a release PATCH ([357a39f](https://github.com/aburan28/cairn/commit/357a39f90b830b454774cb0d9b9b8a9fb4fb1455))
* **sandbox:** drop single-element loop flagged by clippy 1.99 ([8294dc0](https://github.com/aburan28/cairn/commit/8294dc0a8e4f7911297b14d73bff67fba0c2b119))
* **sandbox:** drop single-item loop clippy 1.99 rejects ([abf79c2](https://github.com/aburan28/cairn/commit/abf79c2b423e1d1475f2c46279e9d15377b6070d))
* **sandbox:** run symlinked interpreters under bwrap; test the jail in CI ([#189](https://github.com/aburan28/cairn/issues/189)) ([f7408a9](https://github.com/aburan28/cairn/commit/f7408a90829767a1cd876619721565190e64f4ad))
* **sandbox:** satisfy clippy 1.99's single_element_loop (ported from [#181](https://github.com/aburan28/cairn/issues/181)) ([8b18cc2](https://github.com/aburan28/cairn/commit/8b18cc22bf81e52d1bfe82bbf2c9abb7db1d9f85))
* **scripts:** wait out the finality delay before settling ([967bafe](https://github.com/aburan28/cairn/commit/967bafe10c900b65bf680cd57f750d798a7da227))
* **sealed:** decode published shares so early garbage cannot stall a reveal; say when a seat's share will not open; wipe AEAD keys ([3047a78](https://github.com/aburan28/cairn/commit/3047a788b4b9175cf6c0385c052a378dd15fde8d))
* **security:** a review pass over the node, verifiers, p2p, apps and release pipeline ([#238](https://github.com/aburan28/cairn/issues/238)) ([c8a7b61](https://github.com/aburan28/cairn/commit/c8a7b61a01af675b1dfe612a59cfc9b5871eb56d))
* **security:** round two — close what [#238](https://github.com/aburan28/cairn/issues/238) left open, and the two checks it left red on main ([f85bfc6](https://github.com/aburan28/cairn/commit/f85bfc602a754ad10ab4036d576b11deb72c6673))
* **seeds:** dial the published list without a bootstrap file ([#247](https://github.com/aburan28/cairn/issues/247)) ([ca16d82](https://github.com/aburan28/cairn/commit/ca16d82aa36df7888da187f07848948d84de6b02))
* serve a sealed log, name the version a dispatch builds, retire a stale warning ([c581cde](https://github.com/aburan28/cairn/commit/c581cde212bedf7450f11ea5852b61e8def6508f))
* **serve:** a refusal reaches the client whole; no private link in public docs ([b3ecbc1](https://github.com/aburan28/cairn/commit/b3ecbc163a40a4af67c4a87031e4f84219065093))
* **serve:** bound request lines, cap connection lifetime and per-address slots, refuse rebinding writes ([0b0c1b8](https://github.com/aburan28/cairn/commit/0b0c1b8e855fb5637c61e812ef9a4f73bda42aa4))
* **smoke:** node-smoke waits for the records it posted, not for any record of their kind ([1325957](https://github.com/aburan28/cairn/commit/1325957dbc4a55f3d54d3f9a814e5a4314ed18bb))
* **smoke:** node-smoke waits for the records it posted, not for any record of their kind ([924de3f](https://github.com/aburan28/cairn/commit/924de3f1a5ce981e229676d70dd75bd7e9a766f9))
* teach the CLI and MCP that an epoch closing is no longer enough ([e4be4f3](https://github.com/aburan28/cairn/commit/e4be4f3003579724c3134562d1e1f7eadc231367))
* **tests:** two more suites were one epoch short ([de662a7](https://github.com/aburan28/cairn/commit/de662a78348be3e0bece3ddad68b35eed42c4a4a))
* the CLI and MCP still assume an epoch closing is enough to settle ([8a48057](https://github.com/aburan28/cairn/commit/8a48057eb7cc6a7e63398fd0f5bfb09ce4eec6ab))
* the piecework demo passed only when the fraud went undetected ([#152](https://github.com/aburan28/cairn/issues/152)) ([9365bcc](https://github.com/aburan28/cairn/commit/9365bcc469c0e8b6dca811bf6db5365febf101b9))
* the rename must not touch wire constants, pinned code, or module names ([812e667](https://github.com/aburan28/cairn/commit/812e6672119853802050d98164eb3acab601cdfc))
* **ui:** compare a checkpoint in its own units, label every number's origin, and put ui/lib under test ([#124](https://github.com/aburan28/cairn/issues/124)) ([d860339](https://github.com/aburan28/cairn/commit/d860339728c92ff72f550cd095380a2313a0ee50))
* **ui:** link nowhere on github.com from the reader or Cairn.app ([4f5bd4e](https://github.com/aburan28/cairn/commit/4f5bd4eda010f1c883252296e8386a559ac6c19a))
* **ui:** link nowhere on github.com from the reader or Cairn.app ([6b95017](https://github.com/aburan28/cairn/commit/6b95017de1b3d68f5587e4ce38e48b312c073be7))
* **ui:** patch Next.js, PostCSS and sharp advisories in the reader's toolchain ([3cabb1f](https://github.com/aburan28/cairn/commit/3cabb1fdfd406fdd09a404966fc760e91e58571c))
* **ui:** render a fresh node's signed-but-empty checkpoint instead of crashing ([#138](https://github.com/aburan28/cairn/issues/138)) ([71e1ad3](https://github.com/aburan28/cairn/commit/71e1ad37b257cf004325b5550d62c3af4078cd14))
* **ui:** simplify objective progress and contribution flow ([d98ba9e](https://github.com/aburan28/cairn/commit/d98ba9e964ed34de40e0ccbc48848f825abbbead)), closes [#270](https://github.com/aburan28/cairn/issues/270)
* **ui:** stop an already-elided hash from being abbreviated a second time ([#150](https://github.com/aburan28/cairn/issues/150)) ([ef633cf](https://github.com/aburan28/cairn/commit/ef633cff36edf903bcf51be968c464a4c53f22c4))
* **ui:** stop three things from refusing to shrink on a phone ([#154](https://github.com/aburan28/cairn/issues/154)) ([58cbefb](https://github.com/aburan28/cairn/commit/58cbefbb95e7175cfe56a5ad322a77b27091c9c5))
* **updates:** read the feed from a fixed release, not releases/latest ([#214](https://github.com/aburan28/cairn/issues/214)) ([38c729d](https://github.com/aburan28/cairn/commit/38c729d4d8f9e21754700fb3a9388764eea5f12e))
* **updates:** the fixed feed only ever moves forward ([#216](https://github.com/aburan28/cairn/issues/216)) ([0d505a8](https://github.com/aburan28/cairn/commit/0d505a846df3179e8eced5efe8826a301a02ca9d))
* **vdf:** a delay beacon has one spelling, real elements and a difficulty floor ([73bbd7b](https://github.com/aburan28/cairn/commit/73bbd7b5d70276e6efd07011751daf6b97242de8))
* **verifiers:** a Lean proof must open with `:=`, so it cannot widen the pinned statement ([4f8801b](https://github.com/aburan28/cairn/commit/4f8801b854b687c8d51c332e946bd2dbfaa42afa))
* **verifiers:** audit what a compiled Lean theorem rests on, in both implementations ([1fd6b46](https://github.com/aburan28/cairn/commit/1fd6b46887ea55d914d5b1bd35dd14af59cf0a43))
* **verifiers:** refuse a version-manager python shim up front, with the fix ([#234](https://github.com/aburan28/cairn/issues/234)) ([7a506b1](https://github.com/aburan28/cairn/commit/7a506b13afbd4dac36bf22cafc5ceaf856e6adcc))
* **verifiers:** replay a compiled Lean claim through the kernel, in both implementations ([611ce76](https://github.com/aburan28/cairn/commit/611ce765ce31ec3b896dd69132d3318304e767c6))


### Documentation

* a release-ready reference set, and the three defects writing it exposed ([#149](https://github.com/aburan28/cairn/issues/149)) ([7347722](https://github.com/aburan28/cairn/commit/7347722abaaac6bda0e7caa033928561b72fa077))
* **agents:** fix two stale "Known limits" claims ([#101](https://github.com/aburan28/cairn/issues/101)) ([165195a](https://github.com/aburan28/cairn/commit/165195ad02c6bcded175a61940037b22d7cfa6c9))
* bring nine claims back in step with the tree, and name two gaps ([#121](https://github.com/aburan28/cairn/issues/121)) ([d3c835c](https://github.com/aburan28/cairn/commit/d3c835c1026ba8e8327abb16ef5008b53c64a157))
* buy the ILPs an FHE compiler hides, and refuse the compute ([a60920f](https://github.com/aburan28/cairn/commit/a60920f5fae09565b70e26b2e03287610fbb8c17))
* buy the ILPs an FHE compiler hides, and refuse the compute ([400c874](https://github.com/aburan28/cairn/commit/400c8741ff5ce59e0cf76c2e6f3c4fd539444810))
* **ci:** name the setting that makes release-please fail at the last step ([5c04058](https://github.com/aburan28/cairn/commit/5c04058d86685d74433bbfe634a3d51353fd5068))
* design embargo enforcement, and refuse the pairing that would buy it ([a662e78](https://github.com/aburan28/cairn/commit/a662e785a552a0e1eb6f26e6f636968161b6ae08))
* design embargo enforcement, and refuse the pairing that would buy it ([32bde3f](https://github.com/aburan28/cairn/commit/32bde3fe607a23df3c4b490a170980fa9d75afc5))
* design repository-shaped objectives, and name the half of Yukon we refuse ([6702657](https://github.com/aburan28/cairn/commit/6702657bc962875174c852680c6772759d4740e2))
* design repository-shaped objectives, and name the half of Yukon we refuse ([b4ec908](https://github.com/aburan28/cairn/commit/b4ec90879f85220ab665805e37a6dc109335deb4))
* **design:** fleet members -- enrollment in place of network trust, so a rented GPU joins without a tunnel ([#236](https://github.com/aburan28/cairn/issues/236)) ([4d64b56](https://github.com/aburan28/cairn/commit/4d64b56a1ec17007f77a862668ecf0b4804a6ecf))
* **design:** swarm targeting and compute, from ecdsa.fail and Yukon ([e2a0b8c](https://github.com/aburan28/cairn/commit/e2a0b8c721ce92e31d279d932ad804c4f43a080a))
* **design:** swarm targeting and compute, from ecdsa.fail and Yukon ([f7ee892](https://github.com/aburan28/cairn/commit/f7ee892ffbd2ff49b6c9c4bba2b45527a30d9db4))
* draw the embargo argument, four figures ([4ad20d9](https://github.com/aburan28/cairn/commit/4ad20d98ea047230026e48c625e275a3c2dd81a2))
* draw the embargo argument, four figures ([7990a28](https://github.com/aburan28/cairn/commit/7990a28ffa53ba2b3f10e952c63619406eabf722))
* **lab:** the GFPN anchor comparator reproduces its recorded output in `sage` ([512821f](https://github.com/aburan28/cairn/commit/512821fc4cc87d00558be967ad98eae18f90e678))
* **launch:** rent a cairn seed on a cheap Runpod CPU ([2646874](https://github.com/aburan28/cairn/commit/2646874e2968f07d84fa30990d8f5ac655999f01))
* **macos-app:** note attach-to-URL in the settings table ([f56ed1f](https://github.com/aburan28/cairn/commit/f56ed1f5ac5969a77445316e241c4964493573f6))
* **pages:** record why the site is still not published ([#97](https://github.com/aburan28/cairn/issues/97)) ([8e0d265](https://github.com/aburan28/cairn/commit/8e0d265f9c03b12e7738c7ec873cb15785817ee8))
* two checks CI runs that the pre-flight list did not mention ([b182f48](https://github.com/aburan28/cairn/commit/b182f48f986a40e8c8a854f2427f2a1ec6ef54fd))
* what a proof about verification would buy, and what it would cost ([8e78aa9](https://github.com/aburan28/cairn/commit/8e78aa93ec782242516f837bf3e6f00557379810))
* what a proof about verification would buy, and what it would cost ([850e8e4](https://github.com/aburan28/cairn/commit/850e8e4d87d02cd10451ae8156323295bb7474d0))
* what a shared clock would buy, and the priority gap nobody recorded ([048cfa0](https://github.com/aburan28/cairn/commit/048cfa0a619f390546d71f835190c5e4f10b5a4f))
* what a shared clock would buy, and the priority gap nobody recorded ([b0546cb](https://github.com/aburan28/cairn/commit/b0546cbb979ffdfe61d4a5c39328dfa860eeffba))
* what erasure coding prices about identity, and what it does not ([f836a92](https://github.com/aburan28/cairn/commit/f836a92deee091a38504b70b63116ce7e216d310))
* what erasure coding prices about identity, and what it does not ([f6eefbf](https://github.com/aburan28/cairn/commit/f6eefbf9d30eb8c234f101a70bb827d15e521fa7))

## [2.2.2](https://github.com/aburan28/cairn/compare/v2.2.1...v2.2.2) (2026-10-09)


### Fixes

* **progress:** distinguish unavailable checks from rejections ([fdb6e09](https://github.com/aburan28/cairn/commit/fdb6e091b0ac99edc99d02fa8d7ea793ca8155ba))

## [2.2.1](https://github.com/aburan28/cairn/compare/v2.2.0...v2.2.1) (2026-10-09)


### Fixes

* **ui:** simplify objective progress and contribution flow ([d98ba9e](https://github.com/aburan28/cairn/commit/d98ba9e964ed34de40e0ccbc48848f825abbbead)), closes [#270](https://github.com/aburan28/cairn/issues/270)

## [2.2.0](https://github.com/aburan28/cairn/compare/v2.1.0...v2.2.0) (2026-10-09)

### Features

* **work:** manage named contributions and keep verifiers runnable ([#267](https://github.com/aburan28/cairn/issues/267)) ([6d94d51](https://github.com/aburan28/cairn/commit/6d94d51155e9ffc83695c12d685a325133806cab))

## [2.1.0](https://github.com/aburan28/cairn/compare/v2.0.0...v2.1.0) (2026-10-09)


### Features

* **deposit:** campaign key shape with commit markers, upload through grants ([#262](https://github.com/aburan28/cairn/issues/262)) ([60ffa67](https://github.com/aburan28/cairn/commit/60ffa67f755530f68a574969cc5f1180bb3586d7))
* **ui:** show per-result knowledge evidence ([#263](https://github.com/aburan28/cairn/issues/263)) ([96e5936](https://github.com/aburan28/cairn/commit/96e593693d8dc29a0b718f750dea2bd317dc7f90))

## [2.0.0](https://github.com/aburan28/cairn/compare/v1.18.0...v2.0.0) (2026-10-07)


### ⚠ BREAKING CHANGES

* rename proofwork to cairn

### Features

* add make ui target and ecdsa-fail live objective ([3298c7e](https://github.com/aburan28/cairn/commit/3298c7e7c95bcf68fd1f24886f74608cdb88e09e))
* add make ui target and ecdsa-fail live objective ([aa8ad16](https://github.com/aburan28/cairn/commit/aa8ad16bba1761b48697c617f97ff4bf24777c0f))
* **agent:** the host agent -- hardware registration and gVisor/Kata executor jobs under systemd ([d22f080](https://github.com/aburan28/cairn/commit/d22f0807f606ab0d270141e1a952be8be1df5fc1))
* **agent:** the host agent -- hardware registration and gVisor/Kata executor jobs under systemd ([879185e](https://github.com/aburan28/cairn/commit/879185e8179b9e24026a2555474c803b39f5dae6))
* an epoch beacon a sequencer cannot grind ([04f027d](https://github.com/aburan28/cairn/commit/04f027d41cec1334f7a7b6391a33032e1e904d9d))
* an objective pinning alloc-init's published AADP challenge ([5f62d32](https://github.com/aburan28/cairn/commit/5f62d320d2640ee3a2cfd65f565ab0136d81efbe))
* an objective pinning alloc-init's published AADP challenge ([9a56609](https://github.com/aburan28/cairn/commit/9a56609adee7b182e168d44fb528c57e71a04f07))
* **app:** every Contribute role is a button in Cairn.app, and peers say what they offer ([#249](https://github.com/aburan28/cairn/issues/249)) ([b93dd9a](https://github.com/aburan28/cairn/commit/b93dd9aa7d2840e46b7b7136afb8fc7c1fec3b6a))
* **attest:** the validator loop, knowledge over HTTP, and the first replay example ([#228](https://github.com/aburan28/cairn/issues/228)) ([9bb6daf](https://github.com/aburan28/cairn/commit/9bb6daf08dcc324dc5e056c6bf839fadadbe4fba))
* cairn secret, and an ECC2K-130 DP upload/ingest seam ([#173](https://github.com/aburan28/cairn/issues/173)) ([9cb9657](https://github.com/aburan28/cairn/commit/9cb96579eba3446cbd451ecd67edb5f8a758d7a5))
* citation-flow harness as a CLI, and a CSV export that exports ([#142](https://github.com/aburan28/cairn/issues/142)) ([0e22188](https://github.com/aburan28/cairn/commit/0e22188d7907694ee2d8996f3e598340846ddd1e))
* **cli:** sign live objectives and expose public claims ([d78ef48](https://github.com/aburan28/cairn/commit/d78ef48f63c724d217a4a0ecb2ec4283631484d3))
* crypto autoresearcher end to end over MCP, plus a macOS launcher ([#130](https://github.com/aburan28/cairn/issues/130)) ([f10685d](https://github.com/aburan28/cairn/commit/f10685dbcea3219504b8825aa3e6f87dba627e57))
* deposit grants for mediated cloud uploads ([#174](https://github.com/aburan28/cairn/issues/174)) ([7d289dd](https://github.com/aburan28/cairn/commit/7d289dd405bec7cfa1c1a5e10266106bbae2f5a4))
* **ecc2k:** CPU end-to-end — walk, strip, verify-local, witness ([dd52bff](https://github.com/aburan28/cairn/commit/dd52bffa85d94c53ec9a6295004da5d54eca476b))
* ECDLP objectives -- Certicom's frontier, and a ladder you can climb ([67f4a1a](https://github.com/aburan28/cairn/commit/67f4a1a85d6791b23e52a9da4a273e9348f28592))
* ECDLP objectives — Certicom's frontier, and a ladder you can climb ([ca99a2e](https://github.com/aburan28/cairn/commit/ca99a2eb1b99440d8576b786820633338b0e3265))
* erasure-coded shards, with a Merkle commitment per chunk ([ace2e4c](https://github.com/aburan28/cairn/commit/ace2e4c0fe29e05f46ac9597ba4b2460509a4056))
* erasure-coded shards, with a Merkle commitment per chunk ([c0dee58](https://github.com/aburan28/cairn/commit/c0dee5896573c92128dc09d77313e430fb1a9e25))
* **examples:** differential-path bounties for MD4, MD5, SHA-0 and SHA-1 ([#127](https://github.com/aburan28/cairn/issues/127)) ([08979b5](https://github.com/aburan28/cairn/commit/08979b5621c61297e2ba10a791fd2363fc1b0a49))
* **fleet:** a leader that signs and is paid, workers on your own network, a private peer allowlist, Linux units, and the Mac node as an opt-in launchd agent ([9d82f66](https://github.com/aburan28/cairn/commit/9d82f66877109f76bfe6f0ec45e1890448ea987b))
* **fleet:** a leader that signs and is paid, workers on your own network, a private peer allowlist, Linux units, and the Mac node as an opt-in launchd agent ([809e659](https://github.com/aburan28/cairn/commit/809e659d3d8c917d4bc1d76c1ecb081514ecfa57))
* **fleet:** members enrolled from anywhere, reasons on every submission, underserved angles, and a payouts design ([ff568de](https://github.com/aburan28/cairn/commit/ff568de06495709e731583d0aefb1d73b2faa78a))
* **goals:** goals and angles -- one problem, many approaches -- read off the goal handle, with a catalog that joins two spellings, find_goal before posting, a Goals page, and dictation in New Challenge ([#230](https://github.com/aburan28/cairn/issues/230)) ([3921d18](https://github.com/aburan28/cairn/commit/3921d18d4fe7fbd403c7017fb4fd6c53be2857b4))
* **gui:** discover the models each AI provider serves in Settings → AI ([#212](https://github.com/aburan28/cairn/issues/212)) ([51defca](https://github.com/aburan28/cairn/commit/51defca97bcf04bd34409d87dd9598a960c0f28b))
* install the release binaries without a toolchain ([916d7fd](https://github.com/aburan28/cairn/commit/916d7fd7b5697983d1d64d0b7b264727152cdb9f))
* install the release binaries without a toolchain ([0f1481a](https://github.com/aburan28/cairn/commit/0f1481a59572f28d97f9c65f5a21676a91dee2ed))
* install with curl, and one process instead of three ([c31b4ee](https://github.com/aburan28/cairn/commit/c31b4eee7bf0bd47b670c76ae5a7bdbad76a0c1f))
* **ios:** a Task progress screen, from the node's /progress route ([#222](https://github.com/aburan28/cairn/issues/222)) ([f6332cd](https://github.com/aburan28/cairn/commit/f6332cd4fcbdb03f780e5982746917a49a53eec1))
* **ios:** frontier history, and stop a late log fetch undoing fallback ([#157](https://github.com/aburan28/cairn/issues/157)) ([e5ce3e9](https://github.com/aburan28/cairn/commit/e5ce3e9cb17ac3ea93041c611f3e533640272219))
* **lab:** a replicated research workspace — signed op CRDT, sync, and gVisor runs ([3e44934](https://github.com/aburan28/cairn/commit/3e4493445311cc0a08d95567dc5c3ecdee35e5a8))
* **lab:** lab-demo.sh, honest exit codes, and a forced checkout that restores ([59bc69d](https://github.com/aburan28/cairn/commit/59bc69ddb8fc6b909149a5372f034a13facf40ea))
* **macos:** a real app icon for Cairn.app ([#203](https://github.com/aburan28/cairn/issues/203)) ([2beee5f](https://github.com/aburan28/cairn/commit/2beee5fe22dbb76d47125cdeeef5f1c241d7843a))
* **macos:** AI-drafted challenges, Tasks without a checkout, and a connectivity test ([#200](https://github.com/aburan28/cairn/issues/200)) ([8981801](https://github.com/aburan28/cairn/commit/8981801475be4baf0439bb5064520472a41f9632))
* **macos:** announce peers, attach to a URL, and reader-side checks ([ac17fd8](https://github.com/aburan28/cairn/commit/ac17fd8f0fd6b570ac83dd66b0619b87ff4244dc))
* **macos:** announce peers, attach to a URL, and reader-side checks ([1c43da2](https://github.com/aburan28/cairn/commit/1c43da2653ed6198c630ef5d7f38607c203f8f09))
* **macos:** check for updates in Cairn.app and show its version ([#197](https://github.com/aburan28/cairn/issues/197)) ([d342181](https://github.com/aburan28/cairn/commit/d34218181400ed44fc65933b45ce1da51fd2fd59))
* **macos:** Check for Updates in Cairn.app, and show versions ([#196](https://github.com/aburan28/cairn/issues/196)) ([785b534](https://github.com/aburan28/cairn/commit/785b534ff4510aad0fda1e1b378df4e2393cc15b))
* **macos:** drafted challenges are Lean theorems, with real progress and the toolchain found ([08930a9](https://github.com/aburan28/cairn/commit/08930a9b912e67b8ff8066c4e998e20d7d52866f))
* **macos:** Lean-only drafting with streamed progress, the toolchain found and handed to the node, and Connect an Agent ([bf48468](https://github.com/aburan28/cairn/commit/bf48468f30d964c8b2d076b4aae8298ff12b55ed))
* **macos:** Lean-only drafting with streamed progress, the toolchain found and handed to the node, and Connect an Agent ([#224](https://github.com/aburan28/cairn/issues/224)) ([bf48468](https://github.com/aburan28/cairn/commit/bf48468f30d964c8b2d076b4aae8298ff12b55ed))
* **macos:** limit what Cairn.app's node may use, and choose its data folder ([#164](https://github.com/aburan28/cairn/issues/164)) ([1715e4e](https://github.com/aburan28/cairn/commit/1715e4e57082dab3cf2216db1918c3db4b8c91ec))
* **macos:** make Cairn.app join the network, and harden the Autoresearcher ([a44c42f](https://github.com/aburan28/cairn/commit/a44c42fbf7c63f4bda127a25390a2662c9ca058f))
* **macos:** make Cairn.app join the network, and harden the Autoresearcher ([d100812](https://github.com/aburan28/cairn/commit/d10081236f10151e7632ff3cd33b1aab6d751a75))
* **macos:** Node → Connect an Agent…, the MCP stanza with this Mac's paths in it ([08fc9a9](https://github.com/aburan28/cairn/commit/08fc9a97caa706b428ced1be39b1494a8fc7877d))
* **macos:** paste named secrets in the GUI ([#179](https://github.com/aburan28/cairn/issues/179)) ([6a73cf9](https://github.com/aburan28/cairn/commit/6a73cf9134b81b1b963d011bf2d1fd04f32dee0f))
* **macos:** post-quantum (ML-DSA-87) signatures on Cairn.app updates ([#204](https://github.com/aburan28/cairn/issues/204)) ([4025336](https://github.com/aburan28/cairn/commit/4025336c064a816209871ed50671482ea0f3edac))
* **macos:** ship Cairn.app in the .dmg ([#162](https://github.com/aburan28/cairn/issues/162)) ([db1f17e](https://github.com/aburan28/cairn/commit/db1f17e45418b3a6439a054bddc05e4801abcb27))
* make the us-west seed real ([#139](https://github.com/aburan28/cairn/issues/139)) ([e182c7c](https://github.com/aburan28/cairn/commit/e182c7c116603270f378270a065db224d667d6ad))
* **mcp:** surface a claim's standing where an agent will actually see it ([51f0720](https://github.com/aburan28/cairn/commit/51f0720a0f0bf511dfb02af759347593f681f635))
* native iOS reader and a phone-installable site ([#155](https://github.com/aburan28/cairn/issues/155)) ([014c3e0](https://github.com/aburan28/cairn/commit/014c3e051f7ad9c99de991f7be6f0ecbfd9bfc3e))
* **network:** live sessions, the compute roster, advisory leases and declared roles, with Network and Coordination pages ([d8c935e](https://github.com/aburan28/cairn/commit/d8c935eed30b86a49e7e628bf384cebc7e57f31f))
* **network:** live sessions, the compute roster, advisory leases and declared roles, with Network and Coordination pages ([d6da24f](https://github.com/aburan28/cairn/commit/d6da24fb9143f2af41d996c9d40ce591a7d9ccda))
* one `cairn` binary — `run` serves MCP, the other binaries become subcommands, `make build` stages bin/ ([#128](https://github.com/aburan28/cairn/issues/128)) ([6897143](https://github.com/aburan28/cairn/commit/689714325b9f5e8b9f4300cc389160e29105b205))
* **p2p:** port mapping wired into the daemon -- NAT-PMP, then UPnP IGD -- reported as a claim beside the evidence, with a two-node runbook and a no-GitHub-links guard ([e00cc03](https://github.com/aburan28/cairn/commit/e00cc0309042dbe58434379e25fa1113e107baa7))
* **p2p:** port mapping wired into the daemon (NAT-PMP, then UPnP), reported as a claim beside the evidence; a two-node runbook; no reader links to github.com ([6d7d128](https://github.com/aburan28/cairn/commit/6d7d12861ef3907ffd5cbdbfaaad7c4ad225b6ac))
* **progress:** a per-task dashboard for a divided search, from the log and from worker heartbeats ([87e7e82](https://github.com/aburan28/cairn/commit/87e7e82ab70c2f3379496474c01d1f9e01807c3b))
* **progress:** a per-task dashboard for a divided search, from the log and from worker heartbeats ([335d68e](https://github.com/aburan28/cairn/commit/335d68e459b5f6f05aa8f100cca4cffc85c297dc))
* **progress:** point the autoresearcher GUI and the MCP tool at the task dashboard ([1d78056](https://github.com/aburan28/cairn/commit/1d780568e6f9342ed3e31de75d9b1c50761d4e4e))
* **progress:** point the autoresearcher GUI and the MCP tool at the task dashboard ([5706bd0](https://github.com/aburan28/cairn/commit/5706bd021dc48f0099da69837eb2b317554f4c51))
* publish seed node endpoints on GitHub Pages ([#137](https://github.com/aburan28/cairn/issues/137)) ([31eeb6c](https://github.com/aburan28/cairn/commit/31eeb6c36110c0b14059cbc311b2e959bb70f0e1))
* readable reader, LAN workers with `cairn work`, and roles priced honestly ([#231](https://github.com/aburan28/cairn/issues/231)) ([749de36](https://github.com/aburan28/cairn/commit/749de36a54f066e71fd35b28c16a12eb2c8c6493))
* **release:** ship a .dmg, a .deb and an .rpm ([#161](https://github.com/aburan28/cairn/issues/161)) ([1a16c45](https://github.com/aburan28/cairn/commit/1a16c4526df50566a1f64c95fea73cec9474cb9e))
* rename proofwork to cairn ([940e21a](https://github.com/aburan28/cairn/commit/940e21a943087b04009ce0b44463f91f26c6228c))
* **sealed:** committee shares are checkable on their own, and the reference decodes envelopes ([854307f](https://github.com/aburan28/cairn/commit/854307f90ea42f38d645d0c2e731756cc0f9c3a7))
* **sealed:** the dealer commits to its sharing and answers for every seat, in both implementations ([c47d947](https://github.com/aburan28/cairn/commit/c47d94717df8946f75204bd0e8f691ad6a401df8))
* **secret:** path, env remapping, and ECC2K status helpers ([#172](https://github.com/aburan28/cairn/issues/172)) ([bdcc552](https://github.com/aburan28/cairn/commit/bdcc552721ec4cae5412747b66385dea2a09db10))
* **serve:** optional Google sign-in, anonymous by default ([#245](https://github.com/aburan28/cairn/issues/245)) ([862ed71](https://github.com/aburan28/cairn/commit/862ed71ac183fcfdf084370e6afeed3259abff26))
* settle on the clock, not on arrival order ([7fbae4b](https://github.com/aburan28/cairn/commit/7fbae4bef1507540187dc1d8c8175777f9e60bc6))
* settle on the clock, not on arrival order (re-target to main) ([816efa1](https://github.com/aburan28/cairn/commit/816efa15b1153c7cc62d611cb1ba5a1a5146030a))
* **site:** publish to Pages, and add the two pages a visitor needs ([#95](https://github.com/aburan28/cairn/issues/95)) ([ff10af2](https://github.com/aburan28/cairn/commit/ff10af295069e45d80e944958f45981be36304ee))
* typed claim relations, and a knowledge view nobody has to agree with ([243333f](https://github.com/aburan28/cairn/commit/243333f1211aa1ec08441fe9904914a0f10550e8))
* typed claim relations, and a knowledge view nobody has to agree with ([eb23ea2](https://github.com/aburan28/cairn/commit/eb23ea23d4a3bcad367fc57b2c275c96bbd26c00))
* **ui:** a cairn site whose numbers are re-derivable ([acc6e39](https://github.com/aburan28/cairn/commit/acc6e39e3fc8d00eb41e3af1748e88a1b6acaf7b))
* **ui:** a records explorer and a frontier page ([#116](https://github.com/aburan28/cairn/issues/116)) ([17919cf](https://github.com/aburan28/cairn/commit/17919cf29151d015d6f2a2737d48d3f9025e3246))
* **ui:** app layout for the reader and Cairn.app ([#193](https://github.com/aburan28/cairn/issues/193)) ([90a7645](https://github.com/aburan28/cairn/commit/90a76458d04446aeda3772741fcf8db0df65d2bd))
* **ui:** green palette, voice challenge entry, and network topology ([#232](https://github.com/aburan28/cairn/issues/232)) ([d82a65c](https://github.com/aburan28/cairn/commit/d82a65c6d50c6e83305ab87df546c7e25b8af7a6))
* **ui:** post a challenge from a plain description in Cairn.app ([#206](https://github.com/aburan28/cairn/issues/206)) ([32f0d13](https://github.com/aburan28/cairn/commit/32f0d13442b64b562f0bb5a4ae9989492962794c))
* **ui:** redesigned reader, post challenges from the page, wallet-signed funding ([#131](https://github.com/aburan28/cairn/issues/131)) ([5fc3aee](https://github.com/aburan28/cairn/commit/5fc3aee0f3b86b63d117e12dc961358d73506e13))
* **ui:** your node's role, agents and events, coordinated tasks from a description, and verified results ([2557992](https://github.com/aburan28/cairn/commit/255799231fb95081f4a6bff6c14086007465bfa0))
* **vdf:** the reference checks delay proofs, and a reader can demand more delay than the floor ([919be6c](https://github.com/aburan28/cairn/commit/919be6c2bbb4a3d1a56d42119dd6a62cd7bf7934))
* **verifiers:** GET /verifiers, a Lean control run, and CAIRN_LEAN / CAIRN_LEAN_ROOT ([a166899](https://github.com/aburan28/cairn/commit/a1668994a9bb95fc30a327a07785298c288a6ddd))
* **verifiers:** workspace kind in both implementations ([#187](https://github.com/aburan28/cairn/issues/187)) ([43cac5c](https://github.com/aburan28/cairn/commit/43cac5c52f7834b51af56968b5605f8bb85c435b))


### Fixes

* a retraction needs the target's key, not a matching name ([ec66fee](https://github.com/aburan28/cairn/commit/ec66fee330ed125c1e95512e2cc2bb0dbc65de9c))
* a retraction needs the target's key, not a matching name ([8ef5751](https://github.com/aburan28/cairn/commit/8ef575113808a4d54d25e370543d23934c64d877))
* **agent,mcp:** no engine options through a job's image, the operator's sandbox is a floor, bounded node answers, create-only MCP secrets ([6cff3a3](https://github.com/aburan28/cairn/commit/6cff3a3df684d9f70018152c33582f17cda567ab))
* **canonical:** parse JSON in linear time; one path buffer, not a copy per element ([60740aa](https://github.com/aburan28/cairn/commit/60740aa98f18056d28697165049bc06949928125))
* **ci:** scripts/shard-demo.sh and mcp-config.sh lost their +x bit ([4b21d2f](https://github.com/aburan28/cairn/commit/4b21d2f3c1f8dacd7800216a66cfbf03b0051782))
* decode and canon without a log, like check already did ([#140](https://github.com/aburan28/cairn/issues/140)) ([8a9ec96](https://github.com/aburan28/cairn/commit/8a9ec960e8b3f688572f896fea99ff52bbfb088a))
* **deposit:** S3 uploads are bound to an exact length and checksum, and one address cannot hold every grant ([aabb199](https://github.com/aburan28/cairn/commit/aabb1999d1728c8a77ef7f8a5b0cacb3a562819e))
* **docs:** cargo doc -D warnings fails on main, independent of this branch ([26bb71d](https://github.com/aburan28/cairn/commit/26bb71d888b1d9037fa0f7cb8508b2a4c5c56d02))
* examples/ecdlp was a bounty whose author knew the answer ([f80b478](https://github.com/aburan28/cairn/commit/f80b478908ed06a8816c119db19bad614456c861))
* examples/ecdlp was a bounty whose author knew the answer ([906d2e9](https://github.com/aburan28/cairn/commit/906d2e9fbc8f3f0c91a11996817aad3ed4fd87a7))
* **gui:** Mac bootstrap launch bug and iOS App Store blockers ([84cf759](https://github.com/aburan28/cairn/commit/84cf759ac5e0a4f101c703287e237a75a9144dab))
* **gui:** restart without freezing Cairn.app; staple the installer pkg ([e7701dd](https://github.com/aburan28/cairn/commit/e7701dd559850cf01438908febbaaa404faa863b))
* **gui:** restart without freezing Cairn.app; staple the installer pkg ([490afd4](https://github.com/aburan28/cairn/commit/490afd4009166f5435f239effdb56b17ca165fcb))
* **gui:** unblock bootstrap launches on macOS, clear iOS App Store blockers ([c491681](https://github.com/aburan28/cairn/commit/c491681d352f563cc0c3d83e8117bcc39f81e609))
* **ios:** keep refresh writes on the generation that started them ([#158](https://github.com/aburan28/cairn/issues/158)) ([36bedf6](https://github.com/aburan28/cairn/commit/36bedf6db1603e25d74fc46a2df19579ae020933))
* **lab:** a run never writes into its environment; Sage and PARI environments ([2f0c5c1](https://github.com/aburan28/cairn/commit/2f0c5c1a14708e7c84637aa2573a94870c1065df))
* **launch:** publish the Runpod CPU seed ([9d94811](https://github.com/aburan28/cairn/commit/9d948116b8d0eb4f8bb141183fe38818dcfa1ab2))
* **macos:** compile drafted Lean in the node's jail; open only clicked web links; keep SSE blank lines ([856e2be](https://github.com/aburan28/cairn/commit/856e2bed88d5f45a3a15935e73ee0088e0da2b24))
* **macos:** let the Settings window scroll instead of running off screen ([#201](https://github.com/aburan28/cairn/issues/201)) ([90b5eda](https://github.com/aburan28/cairn/commit/90b5edac18c946b891b3da98832b8d58026af8aa))
* **mcp:** agents fund objectives only within the operator's ceiling, and take the network only with leave ([58da5e4](https://github.com/aburan28/cairn/commit/58da5e471b60f1e72ead1d81911ea6a925a76366))
* measure a log's epoch length instead of guessing at it ([d40b139](https://github.com/aburan28/cairn/commit/d40b1392ab9b15513d6910166e25af31d29af8bc))
* measure a log's epoch length instead of guessing at it ([159eb39](https://github.com/aburan28/cairn/commit/159eb398297d30ac275e5e0551308479575e10ca))
* omit structuredContent when there are no citations to carry ([#141](https://github.com/aburan28/cairn/issues/141)) ([926e608](https://github.com/aburan28/cairn/commit/926e608c396231e9aebafefa845400330634a1ed))
* **ops:** hardened units, a Pages build that cannot publish, signing secrets behind an environment, a drand fetch one relay cannot stop ([99bc5bb](https://github.com/aburan28/cairn/commit/99bc5bba5f2387b8de971a603c692231a50bb88f))
* **p2p:** dial the published seeds by default, and say when one is down ([24b9e5c](https://github.com/aburan28/cairn/commit/24b9e5c9b708d62dbfcf880530e02810230a210f))
* **p2p:** dial the published seeds by default, and say when one is down ([3b01df0](https://github.com/aburan28/cairn/commit/3b01df00b2c5df1219ce4ab4aae13ff40ce7d11f))
* proxied requests are not fleet members, UPnP stays on the host that answered, secrets stay off argv, runs cannot fill the disk, leases have a ceiling ([359f9db](https://github.com/aburan28/cairn/commit/359f9db4bf64f56f34be4b48bb6cae51c11fd7a2))
* public-coin seeds are evidence, not branding ([3c121ce](https://github.com/aburan28/cairn/commit/3c121ce59769aa1da5fe0b0bdee3c9b3979528ea))
* public-coin seeds are evidence, not branding ([586d166](https://github.com/aburan28/cairn/commit/586d166da800a27e19f54795c1c2449b2b9478f2))
* **reference:** rustfmt the drift blocking [#116](https://github.com/aburan28/cairn/issues/116)'s reference job ([#118](https://github.com/aburan28/cairn/issues/118)) ([2aa56e8](https://github.com/aburan28/cairn/commit/2aa56e82ba3282414400b0fab92b055d89fe5d2b))
* refuse to settle a log under a changed epoch length ([4aa2148](https://github.com/aburan28/cairn/commit/4aa214819f43f1d4cf8da64f1fd73f2ef320d8bb))
* refuse to settle a log under a changed epoch length ([7cf0df4](https://github.com/aburan28/cairn/commit/7cf0df41682b489a5fea7982c4d1daebc9c3eb97))
* **release:** a release becomes latest only once it is complete ([96b7895](https://github.com/aburan28/cairn/commit/96b789559453c57857824e6f5cd0bd33a0012f11))
* **release:** a release becomes latest only once it is complete ([ec6cc2b](https://github.com/aburan28/cairn/commit/ec6cc2b6adff6a4040b0853ae7835f8e9331c604))
* **release:** build on tag creation, not only tag push ([#135](https://github.com/aburan28/cairn/issues/135)) ([9fe6f5e](https://github.com/aburan28/cairn/commit/9fe6f5edd0eb339ed0dfe12fb898355a48fda89e))
* **release:** create releases as drafts; publish as prereleases before building ([#221](https://github.com/aburan28/cairn/issues/221)) ([8d20043](https://github.com/aburan28/cairn/commit/8d20043801a99e9dcddc316d2dc6fab3f0264092))
* **release:** scope write tokens per job, pin third-party actions, protect published assets and the feed ([8b7ebd8](https://github.com/aburan28/cairn/commit/8b7ebd829b0c9e254b1cfc8f0b1f10cddb3367cd))
* **release:** start the build when release-please cuts a tag ([1a16c45](https://github.com/aburan28/cairn/commit/1a16c4526df50566a1f64c95fea73cec9474cb9e))
* **release:** stop the build erasing the changelog from the release page ([1a16c45](https://github.com/aburan28/cairn/commit/1a16c4526df50566a1f64c95fea73cec9474cb9e))
* **release:** upload assets with gh release upload, not a release PATCH ([96abb54](https://github.com/aburan28/cairn/commit/96abb543f2c3b2f0fe982f23b961406f8fa82dd7))
* **release:** upload assets with gh release upload, not a release PATCH ([357a39f](https://github.com/aburan28/cairn/commit/357a39f90b830b454774cb0d9b9b8a9fb4fb1455))
* **sandbox:** drop single-element loop flagged by clippy 1.99 ([8294dc0](https://github.com/aburan28/cairn/commit/8294dc0a8e4f7911297b14d73bff67fba0c2b119))
* **sandbox:** drop single-item loop clippy 1.99 rejects ([abf79c2](https://github.com/aburan28/cairn/commit/abf79c2b423e1d1475f2c46279e9d15377b6070d))
* **sandbox:** run symlinked interpreters under bwrap; test the jail in CI ([#189](https://github.com/aburan28/cairn/issues/189)) ([f7408a9](https://github.com/aburan28/cairn/commit/f7408a90829767a1cd876619721565190e64f4ad))
* **sandbox:** satisfy clippy 1.99's single_element_loop (ported from [#181](https://github.com/aburan28/cairn/issues/181)) ([8b18cc2](https://github.com/aburan28/cairn/commit/8b18cc22bf81e52d1bfe82bbf2c9abb7db1d9f85))
* **scripts:** wait out the finality delay before settling ([967bafe](https://github.com/aburan28/cairn/commit/967bafe10c900b65bf680cd57f750d798a7da227))
* **sealed:** decode published shares so early garbage cannot stall a reveal; say when a seat's share will not open; wipe AEAD keys ([3047a78](https://github.com/aburan28/cairn/commit/3047a788b4b9175cf6c0385c052a378dd15fde8d))
* **security:** a review pass over the node, verifiers, p2p, apps and release pipeline ([#238](https://github.com/aburan28/cairn/issues/238)) ([c8a7b61](https://github.com/aburan28/cairn/commit/c8a7b61a01af675b1dfe612a59cfc9b5871eb56d))
* **security:** round two — close what [#238](https://github.com/aburan28/cairn/issues/238) left open, and the two checks it left red on main ([f85bfc6](https://github.com/aburan28/cairn/commit/f85bfc602a754ad10ab4036d576b11deb72c6673))
* **seeds:** dial the published list without a bootstrap file ([#247](https://github.com/aburan28/cairn/issues/247)) ([ca16d82](https://github.com/aburan28/cairn/commit/ca16d82aa36df7888da187f07848948d84de6b02))
* serve a sealed log, name the version a dispatch builds, retire a stale warning ([c581cde](https://github.com/aburan28/cairn/commit/c581cde212bedf7450f11ea5852b61e8def6508f))
* **serve:** a refusal reaches the client whole; no private link in public docs ([b3ecbc1](https://github.com/aburan28/cairn/commit/b3ecbc163a40a4af67c4a87031e4f84219065093))
* **serve:** bound request lines, cap connection lifetime and per-address slots, refuse rebinding writes ([0b0c1b8](https://github.com/aburan28/cairn/commit/0b0c1b8e855fb5637c61e812ef9a4f73bda42aa4))
* **smoke:** node-smoke waits for the records it posted, not for any record of their kind ([1325957](https://github.com/aburan28/cairn/commit/1325957dbc4a55f3d54d3f9a814e5a4314ed18bb))
* **smoke:** node-smoke waits for the records it posted, not for any record of their kind ([924de3f](https://github.com/aburan28/cairn/commit/924de3f1a5ce981e229676d70dd75bd7e9a766f9))
* teach the CLI and MCP that an epoch closing is no longer enough ([e4be4f3](https://github.com/aburan28/cairn/commit/e4be4f3003579724c3134562d1e1f7eadc231367))
* **tests:** two more suites were one epoch short ([de662a7](https://github.com/aburan28/cairn/commit/de662a78348be3e0bece3ddad68b35eed42c4a4a))
* the CLI and MCP still assume an epoch closing is enough to settle ([8a48057](https://github.com/aburan28/cairn/commit/8a48057eb7cc6a7e63398fd0f5bfb09ce4eec6ab))
* the piecework demo passed only when the fraud went undetected ([#152](https://github.com/aburan28/cairn/issues/152)) ([9365bcc](https://github.com/aburan28/cairn/commit/9365bcc469c0e8b6dca811bf6db5365febf101b9))
* the rename must not touch wire constants, pinned code, or module names ([812e667](https://github.com/aburan28/cairn/commit/812e6672119853802050d98164eb3acab601cdfc))
* **ui:** compare a checkpoint in its own units, label every number's origin, and put ui/lib under test ([#124](https://github.com/aburan28/cairn/issues/124)) ([d860339](https://github.com/aburan28/cairn/commit/d860339728c92ff72f550cd095380a2313a0ee50))
* **ui:** link nowhere on github.com from the reader or Cairn.app ([4f5bd4e](https://github.com/aburan28/cairn/commit/4f5bd4eda010f1c883252296e8386a559ac6c19a))
* **ui:** link nowhere on github.com from the reader or Cairn.app ([6b95017](https://github.com/aburan28/cairn/commit/6b95017de1b3d68f5587e4ce38e48b312c073be7))
* **ui:** patch Next.js, PostCSS and sharp advisories in the reader's toolchain ([3cabb1f](https://github.com/aburan28/cairn/commit/3cabb1fdfd406fdd09a404966fc760e91e58571c))
* **ui:** render a fresh node's signed-but-empty checkpoint instead of crashing ([#138](https://github.com/aburan28/cairn/issues/138)) ([71e1ad3](https://github.com/aburan28/cairn/commit/71e1ad37b257cf004325b5550d62c3af4078cd14))
* **ui:** stop an already-elided hash from being abbreviated a second time ([#150](https://github.com/aburan28/cairn/issues/150)) ([ef633cf](https://github.com/aburan28/cairn/commit/ef633cff36edf903bcf51be968c464a4c53f22c4))
* **ui:** stop three things from refusing to shrink on a phone ([#154](https://github.com/aburan28/cairn/issues/154)) ([58cbefb](https://github.com/aburan28/cairn/commit/58cbefbb95e7175cfe56a5ad322a77b27091c9c5))
* **updates:** read the feed from a fixed release, not releases/latest ([#214](https://github.com/aburan28/cairn/issues/214)) ([38c729d](https://github.com/aburan28/cairn/commit/38c729d4d8f9e21754700fb3a9388764eea5f12e))
* **updates:** the fixed feed only ever moves forward ([#216](https://github.com/aburan28/cairn/issues/216)) ([0d505a8](https://github.com/aburan28/cairn/commit/0d505a846df3179e8eced5efe8826a301a02ca9d))
* **vdf:** a delay beacon has one spelling, real elements and a difficulty floor ([73bbd7b](https://github.com/aburan28/cairn/commit/73bbd7b5d70276e6efd07011751daf6b97242de8))
* **verifiers:** a Lean proof must open with `:=`, so it cannot widen the pinned statement ([4f8801b](https://github.com/aburan28/cairn/commit/4f8801b854b687c8d51c332e946bd2dbfaa42afa))
* **verifiers:** audit what a compiled Lean theorem rests on, in both implementations ([1fd6b46](https://github.com/aburan28/cairn/commit/1fd6b46887ea55d914d5b1bd35dd14af59cf0a43))
* **verifiers:** refuse a version-manager python shim up front, with the fix ([#234](https://github.com/aburan28/cairn/issues/234)) ([7a506b1](https://github.com/aburan28/cairn/commit/7a506b13afbd4dac36bf22cafc5ceaf856e6adcc))
* **verifiers:** replay a compiled Lean claim through the kernel, in both implementations ([611ce76](https://github.com/aburan28/cairn/commit/611ce765ce31ec3b896dd69132d3318304e767c6))


### Documentation

* a release-ready reference set, and the three defects writing it exposed ([#149](https://github.com/aburan28/cairn/issues/149)) ([7347722](https://github.com/aburan28/cairn/commit/7347722abaaac6bda0e7caa033928561b72fa077))
* **agents:** fix two stale "Known limits" claims ([#101](https://github.com/aburan28/cairn/issues/101)) ([165195a](https://github.com/aburan28/cairn/commit/165195ad02c6bcded175a61940037b22d7cfa6c9))
* bring nine claims back in step with the tree, and name two gaps ([#121](https://github.com/aburan28/cairn/issues/121)) ([d3c835c](https://github.com/aburan28/cairn/commit/d3c835c1026ba8e8327abb16ef5008b53c64a157))
* buy the ILPs an FHE compiler hides, and refuse the compute ([a60920f](https://github.com/aburan28/cairn/commit/a60920f5fae09565b70e26b2e03287610fbb8c17))
* buy the ILPs an FHE compiler hides, and refuse the compute ([400c874](https://github.com/aburan28/cairn/commit/400c8741ff5ce59e0cf76c2e6f3c4fd539444810))
* **ci:** name the setting that makes release-please fail at the last step ([5c04058](https://github.com/aburan28/cairn/commit/5c04058d86685d74433bbfe634a3d51353fd5068))
* design embargo enforcement, and refuse the pairing that would buy it ([a662e78](https://github.com/aburan28/cairn/commit/a662e785a552a0e1eb6f26e6f636968161b6ae08))
* design embargo enforcement, and refuse the pairing that would buy it ([32bde3f](https://github.com/aburan28/cairn/commit/32bde3fe607a23df3c4b490a170980fa9d75afc5))
* design repository-shaped objectives, and name the half of Yukon we refuse ([6702657](https://github.com/aburan28/cairn/commit/6702657bc962875174c852680c6772759d4740e2))
* design repository-shaped objectives, and name the half of Yukon we refuse ([b4ec908](https://github.com/aburan28/cairn/commit/b4ec90879f85220ab665805e37a6dc109335deb4))
* **design:** fleet members -- enrollment in place of network trust, so a rented GPU joins without a tunnel ([#236](https://github.com/aburan28/cairn/issues/236)) ([4d64b56](https://github.com/aburan28/cairn/commit/4d64b56a1ec17007f77a862668ecf0b4804a6ecf))
* **design:** swarm targeting and compute, from ecdsa.fail and Yukon ([e2a0b8c](https://github.com/aburan28/cairn/commit/e2a0b8c721ce92e31d279d932ad804c4f43a080a))
* **design:** swarm targeting and compute, from ecdsa.fail and Yukon ([f7ee892](https://github.com/aburan28/cairn/commit/f7ee892ffbd2ff49b6c9c4bba2b45527a30d9db4))
* draw the embargo argument, four figures ([4ad20d9](https://github.com/aburan28/cairn/commit/4ad20d98ea047230026e48c625e275a3c2dd81a2))
* draw the embargo argument, four figures ([7990a28](https://github.com/aburan28/cairn/commit/7990a28ffa53ba2b3f10e952c63619406eabf722))
* **lab:** the GFPN anchor comparator reproduces its recorded output in `sage` ([512821f](https://github.com/aburan28/cairn/commit/512821fc4cc87d00558be967ad98eae18f90e678))
* **launch:** rent a cairn seed on a cheap Runpod CPU ([2646874](https://github.com/aburan28/cairn/commit/2646874e2968f07d84fa30990d8f5ac655999f01))
* **macos-app:** note attach-to-URL in the settings table ([f56ed1f](https://github.com/aburan28/cairn/commit/f56ed1f5ac5969a77445316e241c4964493573f6))
* **pages:** record why the site is still not published ([#97](https://github.com/aburan28/cairn/issues/97)) ([8e0d265](https://github.com/aburan28/cairn/commit/8e0d265f9c03b12e7738c7ec873cb15785817ee8))
* two checks CI runs that the pre-flight list did not mention ([b182f48](https://github.com/aburan28/cairn/commit/b182f48f986a40e8c8a854f2427f2a1ec6ef54fd))
* what a proof about verification would buy, and what it would cost ([8e78aa9](https://github.com/aburan28/cairn/commit/8e78aa93ec782242516f837bf3e6f00557379810))
* what a proof about verification would buy, and what it would cost ([850e8e4](https://github.com/aburan28/cairn/commit/850e8e4d87d02cd10451ae8156323295bb7474d0))
* what a shared clock would buy, and the priority gap nobody recorded ([048cfa0](https://github.com/aburan28/cairn/commit/048cfa0a619f390546d71f835190c5e4f10b5a4f))
* what a shared clock would buy, and the priority gap nobody recorded ([b0546cb](https://github.com/aburan28/cairn/commit/b0546cbb979ffdfe61d4a5c39328dfa860eeffba))
* what erasure coding prices about identity, and what it does not ([f836a92](https://github.com/aburan28/cairn/commit/f836a92deee091a38504b70b63116ce7e216d310))
* what erasure coding prices about identity, and what it does not ([f6eefbf](https://github.com/aburan28/cairn/commit/f6eefbf9d30eb8c234f101a70bb827d15e521fa7))

## [1.18.0](https://github.com/aburan28/cairn/compare/v1.17.0...v1.18.0) (2026-10-07)


### Features

* **app:** every Contribute role is a button in Cairn.app, and peers say what they offer ([#249](https://github.com/aburan28/cairn/issues/249)) ([b93dd9a](https://github.com/aburan28/cairn/commit/b93dd9aa7d2840e46b7b7136afb8fc7c1fec3b6a))
* **cli:** sign live objectives and expose public claims ([d78ef48](https://github.com/aburan28/cairn/commit/d78ef48f63c724d217a4a0ecb2ec4283631484d3))
* **fleet:** members enrolled from anywhere, reasons on every submission, underserved angles, and a payouts design ([ff568de](https://github.com/aburan28/cairn/commit/ff568de06495709e731583d0aefb1d73b2faa78a))
* **serve:** optional Google sign-in, anonymous by default ([#245](https://github.com/aburan28/cairn/issues/245)) ([862ed71](https://github.com/aburan28/cairn/commit/862ed71ac183fcfdf084370e6afeed3259abff26))


### Fixes

* **launch:** publish the Runpod CPU seed ([9d94811](https://github.com/aburan28/cairn/commit/9d948116b8d0eb4f8bb141183fe38818dcfa1ab2))
* **seeds:** dial the published list without a bootstrap file ([#247](https://github.com/aburan28/cairn/issues/247)) ([ca16d82](https://github.com/aburan28/cairn/commit/ca16d82aa36df7888da187f07848948d84de6b02))


### Documentation

* **launch:** rent a cairn seed on a cheap Runpod CPU ([2646874](https://github.com/aburan28/cairn/commit/2646874e2968f07d84fa30990d8f5ac655999f01))

## [1.17.0](https://github.com/aburan28/cairn/compare/v1.16.0...v1.17.0) (2026-10-05)


### Features

* readable reader, LAN workers with `cairn work`, and roles priced honestly ([#231](https://github.com/aburan28/cairn/issues/231)) ([749de36](https://github.com/aburan28/cairn/commit/749de36a54f066e71fd35b28c16a12eb2c8c6493))
* **ui:** green palette, voice challenge entry, and network topology ([#232](https://github.com/aburan28/cairn/issues/232)) ([d82a65c](https://github.com/aburan28/cairn/commit/d82a65c6d50c6e83305ab87df546c7e25b8af7a6))


### Fixes

* **security:** a review pass over the node, verifiers, p2p, apps and release pipeline ([#238](https://github.com/aburan28/cairn/issues/238)) ([c8a7b61](https://github.com/aburan28/cairn/commit/c8a7b61a01af675b1dfe612a59cfc9b5871eb56d))
* **security:** round two — close what [#238](https://github.com/aburan28/cairn/issues/238) left open, and the two checks it left red on main ([f85bfc6](https://github.com/aburan28/cairn/commit/f85bfc602a754ad10ab4036d576b11deb72c6673))
* **smoke:** node-smoke waits for the records it posted, not for any record of their kind ([1325957](https://github.com/aburan28/cairn/commit/1325957dbc4a55f3d54d3f9a814e5a4314ed18bb))
* **verifiers:** refuse a version-manager python shim up front, with the fix ([#234](https://github.com/aburan28/cairn/issues/234)) ([7a506b1](https://github.com/aburan28/cairn/commit/7a506b13afbd4dac36bf22cafc5ceaf856e6adcc))


### Documentation

* **design:** fleet members -- enrollment in place of network trust, so a rented GPU joins without a tunnel ([#236](https://github.com/aburan28/cairn/issues/236)) ([4d64b56](https://github.com/aburan28/cairn/commit/4d64b56a1ec17007f77a862668ecf0b4804a6ecf))

## [1.16.0](https://github.com/aburan28/cairn/compare/v1.15.3...v1.16.0) (2026-10-04)


### Features

* **agent:** the host agent -- hardware registration and gVisor/Kata executor jobs under systemd ([d22f080](https://github.com/aburan28/cairn/commit/d22f0807f606ab0d270141e1a952be8be1df5fc1))
* **attest:** the validator loop, knowledge over HTTP, and the first replay example ([#228](https://github.com/aburan28/cairn/issues/228)) ([9bb6daf](https://github.com/aburan28/cairn/commit/9bb6daf08dcc324dc5e056c6bf839fadadbe4fba))
* **fleet:** a leader that signs and is paid, workers on your own network, a private peer allowlist, Linux units, and the Mac node as an opt-in launchd agent ([9d82f66](https://github.com/aburan28/cairn/commit/9d82f66877109f76bfe6f0ec45e1890448ea987b))
* **goals:** goals and angles -- one problem, many approaches -- read off the goal handle, with a catalog that joins two spellings, find_goal before posting, a Goals page, and dictation in New Challenge ([#230](https://github.com/aburan28/cairn/issues/230)) ([3921d18](https://github.com/aburan28/cairn/commit/3921d18d4fe7fbd403c7017fb4fd6c53be2857b4))
* **ios:** a Task progress screen, from the node's /progress route ([#222](https://github.com/aburan28/cairn/issues/222)) ([f6332cd](https://github.com/aburan28/cairn/commit/f6332cd4fcbdb03f780e5982746917a49a53eec1))
* **macos:** Lean-only drafting with streamed progress, the toolchain found and handed to the node, and Connect an Agent ([#224](https://github.com/aburan28/cairn/issues/224)) ([bf48468](https://github.com/aburan28/cairn/commit/bf48468f30d964c8b2d076b4aae8298ff12b55ed))
* **network:** live sessions, the compute roster, advisory leases and declared roles, with Network and Coordination pages ([d8c935e](https://github.com/aburan28/cairn/commit/d8c935eed30b86a49e7e628bf384cebc7e57f31f))
* **p2p:** port mapping wired into the daemon (NAT-PMP, then UPnP), reported as a claim beside the evidence; a two-node runbook; no reader links to github.com ([6d7d128](https://github.com/aburan28/cairn/commit/6d7d12861ef3907ffd5cbdbfaaad7c4ad225b6ac))
* **verifiers:** GET /verifiers, a Lean control run, and CAIRN_LEAN / CAIRN_LEAN_ROOT ([a166899](https://github.com/aburan28/cairn/commit/a1668994a9bb95fc30a327a07785298c288a6ddd))


### Fixes

* **release:** create releases as drafts; publish as prereleases before building ([#221](https://github.com/aburan28/cairn/issues/221)) ([8d20043](https://github.com/aburan28/cairn/commit/8d20043801a99e9dcddc316d2dc6fab3f0264092))

## [1.15.3](https://github.com/aburan28/cairn/compare/v1.15.2...v1.15.3) (2026-10-03)


### Fixes

* **release:** a release becomes latest only once it is complete ([96b7895](https://github.com/aburan28/cairn/commit/96b789559453c57857824e6f5cd0bd33a0012f11))
* **release:** a release becomes latest only once it is complete ([ec6cc2b](https://github.com/aburan28/cairn/commit/ec6cc2b6adff6a4040b0853ae7835f8e9331c604))
* **release:** upload assets with gh release upload, not a release PATCH ([96abb54](https://github.com/aburan28/cairn/commit/96abb543f2c3b2f0fe982f23b961406f8fa82dd7))
* **release:** upload assets with gh release upload, not a release PATCH ([357a39f](https://github.com/aburan28/cairn/commit/357a39f90b830b454774cb0d9b9b8a9fb4fb1455))

## [1.15.2](https://github.com/aburan28/cairn/compare/v1.15.1...v1.15.2) (2026-10-03)


### Fixes

* **updates:** the fixed feed only ever moves forward ([#216](https://github.com/aburan28/cairn/issues/216)) ([0d505a8](https://github.com/aburan28/cairn/commit/0d505a846df3179e8eced5efe8826a301a02ca9d))

## [1.15.1](https://github.com/aburan28/cairn/compare/v1.15.0...v1.15.1) (2026-10-03)


### Fixes

* **updates:** read the feed from a fixed release, not releases/latest ([#214](https://github.com/aburan28/cairn/issues/214)) ([38c729d](https://github.com/aburan28/cairn/commit/38c729d4d8f9e21754700fb3a9388764eea5f12e))

## [1.15.0](https://github.com/aburan28/cairn/compare/v1.14.0...v1.15.0) (2026-10-03)


### Features

* **gui:** discover the models each AI provider serves in Settings → AI ([#212](https://github.com/aburan28/cairn/issues/212)) ([51defca](https://github.com/aburan28/cairn/commit/51defca97bcf04bd34409d87dd9598a960c0f28b))


### Fixes

* **ui:** link nowhere on github.com from the reader or Cairn.app ([4f5bd4e](https://github.com/aburan28/cairn/commit/4f5bd4eda010f1c883252296e8386a559ac6c19a))
* **ui:** link nowhere on github.com from the reader or Cairn.app ([6b95017](https://github.com/aburan28/cairn/commit/6b95017de1b3d68f5587e4ce38e48b312c073be7))

## [1.14.0](https://github.com/aburan28/cairn/compare/v1.13.0...v1.14.0) (2026-10-03)


### Features

* **progress:** a per-task dashboard for a divided search, from the log and from worker heartbeats ([87e7e82](https://github.com/aburan28/cairn/commit/87e7e82ab70c2f3379496474c01d1f9e01807c3b))
* **progress:** a per-task dashboard for a divided search, from the log and from worker heartbeats ([335d68e](https://github.com/aburan28/cairn/commit/335d68e459b5f6f05aa8f100cca4cffc85c297dc))
* **progress:** point the autoresearcher GUI and the MCP tool at the task dashboard ([1d78056](https://github.com/aburan28/cairn/commit/1d780568e6f9342ed3e31de75d9b1c50761d4e4e))
* **progress:** point the autoresearcher GUI and the MCP tool at the task dashboard ([5706bd0](https://github.com/aburan28/cairn/commit/5706bd021dc48f0099da69837eb2b317554f4c51))

## [1.13.0](https://github.com/aburan28/cairn/compare/v1.12.0...v1.13.0) (2026-10-03)


### Features

* **ui:** post a challenge from a plain description in Cairn.app ([#206](https://github.com/aburan28/cairn/issues/206)) ([32f0d13](https://github.com/aburan28/cairn/commit/32f0d13442b64b562f0bb5a4ae9989492962794c))

## [1.12.0](https://github.com/aburan28/cairn/compare/v1.11.0...v1.12.0) (2026-10-02)


### Features

* **macos:** post-quantum (ML-DSA-87) signatures on Cairn.app updates ([#204](https://github.com/aburan28/cairn/issues/204)) ([4025336](https://github.com/aburan28/cairn/commit/4025336c064a816209871ed50671482ea0f3edac))

## [1.11.0](https://github.com/aburan28/cairn/compare/v1.10.0...v1.11.0) (2026-10-02)


### Features

* **macos:** a real app icon for Cairn.app ([#203](https://github.com/aburan28/cairn/issues/203)) ([2beee5f](https://github.com/aburan28/cairn/commit/2beee5fe22dbb76d47125cdeeef5f1c241d7843a))
* **macos:** AI-drafted challenges, Tasks without a checkout, and a connectivity test ([#200](https://github.com/aburan28/cairn/issues/200)) ([8981801](https://github.com/aburan28/cairn/commit/8981801475be4baf0439bb5064520472a41f9632))


### Fixes

* **macos:** let the Settings window scroll instead of running off screen ([#201](https://github.com/aburan28/cairn/issues/201)) ([90b5eda](https://github.com/aburan28/cairn/commit/90b5edac18c946b891b3da98832b8d58026af8aa))

## [1.10.0](https://github.com/aburan28/cairn/compare/v1.9.0...v1.10.0) (2026-10-02)


### Features

* **macos:** check for updates in Cairn.app and show its version ([#197](https://github.com/aburan28/cairn/issues/197)) ([d342181](https://github.com/aburan28/cairn/commit/d34218181400ed44fc65933b45ce1da51fd2fd59))

## [1.9.0](https://github.com/aburan28/cairn/compare/v1.8.1...v1.9.0) (2026-10-02)


### Features

* **macos:** Check for Updates in Cairn.app, and show versions ([#196](https://github.com/aburan28/cairn/issues/196)) ([785b534](https://github.com/aburan28/cairn/commit/785b534ff4510aad0fda1e1b378df4e2393cc15b))

## [1.8.1](https://github.com/aburan28/cairn/compare/v1.8.0...v1.8.1) (2026-10-02)


### Fixes

* **sandbox:** run symlinked interpreters under bwrap; test the jail in CI ([#189](https://github.com/aburan28/cairn/issues/189)) ([f7408a9](https://github.com/aburan28/cairn/commit/f7408a90829767a1cd876619721565190e64f4ad))

## [1.8.0](https://github.com/aburan28/cairn/compare/v1.7.0...v1.8.0) (2026-10-02)


### Features

* **ui:** app layout for the reader and Cairn.app ([#193](https://github.com/aburan28/cairn/issues/193)) ([90a7645](https://github.com/aburan28/cairn/commit/90a76458d04446aeda3772741fcf8db0df65d2bd))

## [1.7.0](https://github.com/aburan28/cairn/compare/v1.6.0...v1.7.0) (2026-10-02)


### Features

* **macos:** paste named secrets in the GUI ([#179](https://github.com/aburan28/cairn/issues/179)) ([6a73cf9](https://github.com/aburan28/cairn/commit/6a73cf9134b81b1b963d011bf2d1fd04f32dee0f))

## [1.6.0](https://github.com/aburan28/cairn/compare/v1.5.0...v1.6.0) (2026-10-02)


### Features

* **lab:** a replicated research workspace — signed op CRDT, sync, and gVisor runs ([3e44934](https://github.com/aburan28/cairn/commit/3e4493445311cc0a08d95567dc5c3ecdee35e5a8))
* **lab:** lab-demo.sh, honest exit codes, and a forced checkout that restores ([59bc69d](https://github.com/aburan28/cairn/commit/59bc69ddb8fc6b909149a5372f034a13facf40ea))
* **verifiers:** workspace kind in both implementations ([#187](https://github.com/aburan28/cairn/issues/187)) ([43cac5c](https://github.com/aburan28/cairn/commit/43cac5c52f7834b51af56968b5605f8bb85c435b))


### Fixes

* **gui:** Mac bootstrap launch bug and iOS App Store blockers ([84cf759](https://github.com/aburan28/cairn/commit/84cf759ac5e0a4f101c703287e237a75a9144dab))
* **gui:** restart without freezing Cairn.app; staple the installer pkg ([e7701dd](https://github.com/aburan28/cairn/commit/e7701dd559850cf01438908febbaaa404faa863b))
* **gui:** restart without freezing Cairn.app; staple the installer pkg ([490afd4](https://github.com/aburan28/cairn/commit/490afd4009166f5435f239effdb56b17ca165fcb))
* **gui:** unblock bootstrap launches on macOS, clear iOS App Store blockers ([c491681](https://github.com/aburan28/cairn/commit/c491681d352f563cc0c3d83e8117bcc39f81e609))
* **lab:** a run never writes into its environment; Sage and PARI environments ([2f0c5c1](https://github.com/aburan28/cairn/commit/2f0c5c1a14708e7c84637aa2573a94870c1065df))
* **sandbox:** drop single-element loop flagged by clippy 1.99 ([8294dc0](https://github.com/aburan28/cairn/commit/8294dc0a8e4f7911297b14d73bff67fba0c2b119))
* **sandbox:** drop single-item loop clippy 1.99 rejects ([abf79c2](https://github.com/aburan28/cairn/commit/abf79c2b423e1d1475f2c46279e9d15377b6070d))
* **sandbox:** satisfy clippy 1.99's single_element_loop (ported from [#181](https://github.com/aburan28/cairn/issues/181)) ([8b18cc2](https://github.com/aburan28/cairn/commit/8b18cc22bf81e52d1bfe82bbf2c9abb7db1d9f85))


### Documentation

* **design:** swarm targeting and compute, from ecdsa.fail and Yukon ([e2a0b8c](https://github.com/aburan28/cairn/commit/e2a0b8c721ce92e31d279d932ad804c4f43a080a))
* **design:** swarm targeting and compute, from ecdsa.fail and Yukon ([f7ee892](https://github.com/aburan28/cairn/commit/f7ee892ffbd2ff49b6c9c4bba2b45527a30d9db4))
* **lab:** the GFPN anchor comparator reproduces its recorded output in `sage` ([512821f](https://github.com/aburan28/cairn/commit/512821fc4cc87d00558be967ad98eae18f90e678))

## [1.5.0](https://github.com/aburan28/cairn/compare/v1.4.0...v1.5.0) (2026-09-29)


### Features

* cairn secret, and an ECC2K-130 DP upload/ingest seam ([#173](https://github.com/aburan28/cairn/issues/173)) ([9cb9657](https://github.com/aburan28/cairn/commit/9cb96579eba3446cbd451ecd67edb5f8a758d7a5))
* deposit grants for mediated cloud uploads ([#174](https://github.com/aburan28/cairn/issues/174)) ([7d289dd](https://github.com/aburan28/cairn/commit/7d289dd405bec7cfa1c1a5e10266106bbae2f5a4))
* **macos:** limit what Cairn.app's node may use, and choose its data folder ([#164](https://github.com/aburan28/cairn/issues/164)) ([1715e4e](https://github.com/aburan28/cairn/commit/1715e4e57082dab3cf2216db1918c3db4b8c91ec))
* **macos:** ship Cairn.app in the .dmg ([#162](https://github.com/aburan28/cairn/issues/162)) ([db1f17e](https://github.com/aburan28/cairn/commit/db1f17e45418b3a6439a054bddc05e4801abcb27))

## [1.4.0](https://github.com/aburan28/cairn/compare/v1.3.0...v1.4.0) (2026-09-21)


### Features

* **ios:** frontier history, and stop a late log fetch undoing fallback ([#157](https://github.com/aburan28/cairn/issues/157)) ([e5ce3e9](https://github.com/aburan28/cairn/commit/e5ce3e9cb17ac3ea93041c611f3e533640272219))
* native iOS reader and a phone-installable site ([#155](https://github.com/aburan28/cairn/issues/155)) ([014c3e0](https://github.com/aburan28/cairn/commit/014c3e051f7ad9c99de991f7be6f0ecbfd9bfc3e))
* **release:** ship a .dmg, a .deb and an .rpm ([#161](https://github.com/aburan28/cairn/issues/161)) ([1a16c45](https://github.com/aburan28/cairn/commit/1a16c4526df50566a1f64c95fea73cec9474cb9e))


### Fixes

* **ios:** keep refresh writes on the generation that started them ([#158](https://github.com/aburan28/cairn/issues/158)) ([36bedf6](https://github.com/aburan28/cairn/commit/36bedf6db1603e25d74fc46a2df19579ae020933))
* **release:** start the build when release-please cuts a tag ([1a16c45](https://github.com/aburan28/cairn/commit/1a16c4526df50566a1f64c95fea73cec9474cb9e))
* **release:** stop the build erasing the changelog from the release page ([1a16c45](https://github.com/aburan28/cairn/commit/1a16c4526df50566a1f64c95fea73cec9474cb9e))
* the piecework demo passed only when the fraud went undetected ([#152](https://github.com/aburan28/cairn/issues/152)) ([9365bcc](https://github.com/aburan28/cairn/commit/9365bcc469c0e8b6dca811bf6db5365febf101b9))
* **ui:** stop an already-elided hash from being abbreviated a second time ([#150](https://github.com/aburan28/cairn/issues/150)) ([ef633cf](https://github.com/aburan28/cairn/commit/ef633cff36edf903bcf51be968c464a4c53f22c4))
* **ui:** stop three things from refusing to shrink on a phone ([#154](https://github.com/aburan28/cairn/issues/154)) ([58cbefb](https://github.com/aburan28/cairn/commit/58cbefbb95e7175cfe56a5ad322a77b27091c9c5))


### Documentation

* a release-ready reference set, and the three defects writing it exposed ([#149](https://github.com/aburan28/cairn/issues/149)) ([7347722](https://github.com/aburan28/cairn/commit/7347722abaaac6bda0e7caa033928561b72fa077))

## [1.3.0](https://github.com/aburan28/cairn/compare/v1.2.0...v1.3.0) (2026-09-07)


### Features

* citation-flow harness as a CLI, and a CSV export that exports ([#142](https://github.com/aburan28/cairn/issues/142)) ([0e22188](https://github.com/aburan28/cairn/commit/0e22188d7907694ee2d8996f3e598340846ddd1e))
* make the us-west seed real ([#139](https://github.com/aburan28/cairn/issues/139)) ([e182c7c](https://github.com/aburan28/cairn/commit/e182c7c116603270f378270a065db224d667d6ad))
* publish seed node endpoints on GitHub Pages ([#137](https://github.com/aburan28/cairn/issues/137)) ([31eeb6c](https://github.com/aburan28/cairn/commit/31eeb6c36110c0b14059cbc311b2e959bb70f0e1))
* **ui:** redesigned reader, post challenges from the page, wallet-signed funding ([#131](https://github.com/aburan28/cairn/issues/131)) ([5fc3aee](https://github.com/aburan28/cairn/commit/5fc3aee0f3b86b63d117e12dc961358d73506e13))


### Fixes

* decode and canon without a log, like check already did ([#140](https://github.com/aburan28/cairn/issues/140)) ([8a9ec96](https://github.com/aburan28/cairn/commit/8a9ec960e8b3f688572f896fea99ff52bbfb088a))
* omit structuredContent when there are no citations to carry ([#141](https://github.com/aburan28/cairn/issues/141)) ([926e608](https://github.com/aburan28/cairn/commit/926e608c396231e9aebafefa845400330634a1ed))
* **release:** build on tag creation, not only tag push ([#135](https://github.com/aburan28/cairn/issues/135)) ([9fe6f5e](https://github.com/aburan28/cairn/commit/9fe6f5edd0eb339ed0dfe12fb898355a48fda89e))
* **ui:** render a fresh node's signed-but-empty checkpoint instead of crashing ([#138](https://github.com/aburan28/cairn/issues/138)) ([71e1ad3](https://github.com/aburan28/cairn/commit/71e1ad37b257cf004325b5550d62c3af4078cd14))

## [1.2.0](https://github.com/aburan28/cairn/compare/v1.1.0...v1.2.0) (2026-09-06)


### Features

* crypto autoresearcher end to end over MCP, plus a macOS launcher ([#130](https://github.com/aburan28/cairn/issues/130)) ([f10685d](https://github.com/aburan28/cairn/commit/f10685dbcea3219504b8825aa3e6f87dba627e57))
* **examples:** differential-path bounties for MD4, MD5, SHA-0 and SHA-1 ([#127](https://github.com/aburan28/cairn/issues/127)) ([08979b5](https://github.com/aburan28/cairn/commit/08979b5621c61297e2ba10a791fd2363fc1b0a49))
* one `cairn` binary — `run` serves MCP, the other binaries become subcommands, `make build` stages bin/ ([#128](https://github.com/aburan28/cairn/issues/128)) ([6897143](https://github.com/aburan28/cairn/commit/689714325b9f5e8b9f4300cc389160e29105b205))
* **ui:** a records explorer and a frontier page ([#116](https://github.com/aburan28/cairn/issues/116)) ([17919cf](https://github.com/aburan28/cairn/commit/17919cf29151d015d6f2a2737d48d3f9025e3246))


### Fixes

* **reference:** rustfmt the drift blocking [#116](https://github.com/aburan28/cairn/issues/116)'s reference job ([#118](https://github.com/aburan28/cairn/issues/118)) ([2aa56e8](https://github.com/aburan28/cairn/commit/2aa56e82ba3282414400b0fab92b055d89fe5d2b))
* **ui:** compare a checkpoint in its own units, label every number's origin, and put ui/lib under test ([#124](https://github.com/aburan28/cairn/issues/124)) ([d860339](https://github.com/aburan28/cairn/commit/d860339728c92ff72f550cd095380a2313a0ee50))


### Documentation

* **agents:** fix two stale "Known limits" claims ([#101](https://github.com/aburan28/cairn/issues/101)) ([165195a](https://github.com/aburan28/cairn/commit/165195ad02c6bcded175a61940037b22d7cfa6c9))
* bring nine claims back in step with the tree, and name two gaps ([#121](https://github.com/aburan28/cairn/issues/121)) ([d3c835c](https://github.com/aburan28/cairn/commit/d3c835c1026ba8e8327abb16ef5008b53c64a157))

## [1.1.0](https://github.com/aburan28/cairn/compare/v1.0.1...v1.1.0) (2026-09-06)


### Features

* crypto autoresearcher end to end over MCP, plus a macOS launcher ([#130](https://github.com/aburan28/cairn/issues/130)) ([f10685d](https://github.com/aburan28/cairn/commit/f10685dbcea3219504b8825aa3e6f87dba627e57))
* **examples:** differential-path bounties for MD4, MD5, SHA-0 and SHA-1 ([#127](https://github.com/aburan28/cairn/issues/127)) ([08979b5](https://github.com/aburan28/cairn/commit/08979b5621c61297e2ba10a791fd2363fc1b0a49))
* one `cairn` binary — `run` serves MCP, the other binaries become subcommands, `make build` stages bin/ ([#128](https://github.com/aburan28/cairn/issues/128)) ([6897143](https://github.com/aburan28/cairn/commit/689714325b9f5e8b9f4300cc389160e29105b205))
* **site:** publish to Pages, and add the two pages a visitor needs ([#95](https://github.com/aburan28/cairn/issues/95)) ([ff10af2](https://github.com/aburan28/cairn/commit/ff10af295069e45d80e944958f45981be36304ee))
* **ui:** a records explorer and a frontier page ([#116](https://github.com/aburan28/cairn/issues/116)) ([17919cf](https://github.com/aburan28/cairn/commit/17919cf29151d015d6f2a2737d48d3f9025e3246))


### Fixes

* **reference:** rustfmt the drift blocking [#116](https://github.com/aburan28/cairn/issues/116)'s reference job ([#118](https://github.com/aburan28/cairn/issues/118)) ([2aa56e8](https://github.com/aburan28/cairn/commit/2aa56e82ba3282414400b0fab92b055d89fe5d2b))
* **ui:** compare a checkpoint in its own units, label every number's origin, and put ui/lib under test ([#124](https://github.com/aburan28/cairn/issues/124)) ([d860339](https://github.com/aburan28/cairn/commit/d860339728c92ff72f550cd095380a2313a0ee50))


### Documentation

* **agents:** fix two stale "Known limits" claims ([#101](https://github.com/aburan28/cairn/issues/101)) ([165195a](https://github.com/aburan28/cairn/commit/165195ad02c6bcded175a61940037b22d7cfa6c9))
* bring nine claims back in step with the tree, and name two gaps ([#121](https://github.com/aburan28/cairn/issues/121)) ([d3c835c](https://github.com/aburan28/cairn/commit/d3c835c1026ba8e8327abb16ef5008b53c64a157))
* **pages:** record why the site is still not published ([#97](https://github.com/aburan28/cairn/issues/97)) ([8e0d265](https://github.com/aburan28/cairn/commit/8e0d265f9c03b12e7738c7ec873cb15785817ee8))

## [1.0.1](https://github.com/aburan28/distributed-researcher/compare/v1.0.0...v1.0.1) (2026-08-15)


### Fixes

* public-coin seeds are evidence, not branding ([3c121ce](https://github.com/aburan28/distributed-researcher/commit/3c121ce59769aa1da5fe0b0bdee3c9b3979528ea))


### Documentation

* draw the embargo argument, four figures ([4ad20d9](https://github.com/aburan28/distributed-researcher/commit/4ad20d98ea047230026e48c625e275a3c2dd81a2))

## [1.0.0](https://github.com/aburan28/distributed-researcher/compare/v0.2.0...v1.0.0) (2026-08-15)


### ⚠ BREAKING CHANGES

* rename proofwork to cairn

### Features

* add make ui target and ecdsa-fail live objective ([3298c7e](https://github.com/aburan28/distributed-researcher/commit/3298c7e7c95bcf68fd1f24886f74608cdb88e09e))
* add make ui target and ecdsa-fail live objective ([aa8ad16](https://github.com/aburan28/distributed-researcher/commit/aa8ad16bba1761b48697c617f97ff4bf24777c0f))
* an epoch beacon a sequencer cannot grind ([04f027d](https://github.com/aburan28/distributed-researcher/commit/04f027d41cec1334f7a7b6391a33032e1e904d9d))
* an objective pinning alloc-init's published AADP challenge ([5f62d32](https://github.com/aburan28/distributed-researcher/commit/5f62d320d2640ee3a2cfd65f565ab0136d81efbe))
* an objective pinning alloc-init's published AADP challenge ([9a56609](https://github.com/aburan28/distributed-researcher/commit/9a56609adee7b182e168d44fb528c57e71a04f07))
* ECDLP objectives -- Certicom's frontier, and a ladder you can climb ([67f4a1a](https://github.com/aburan28/distributed-researcher/commit/67f4a1a85d6791b23e52a9da4a273e9348f28592))
* ECDLP objectives — Certicom's frontier, and a ladder you can climb ([ca99a2e](https://github.com/aburan28/distributed-researcher/commit/ca99a2eb1b99440d8576b786820633338b0e3265))
* erasure-coded shards, with a Merkle commitment per chunk ([ace2e4c](https://github.com/aburan28/distributed-researcher/commit/ace2e4c0fe29e05f46ac9597ba4b2460509a4056))
* erasure-coded shards, with a Merkle commitment per chunk ([c0dee58](https://github.com/aburan28/distributed-researcher/commit/c0dee5896573c92128dc09d77313e430fb1a9e25))
* install the release binaries without a toolchain ([916d7fd](https://github.com/aburan28/distributed-researcher/commit/916d7fd7b5697983d1d64d0b7b264727152cdb9f))
* install the release binaries without a toolchain ([0f1481a](https://github.com/aburan28/distributed-researcher/commit/0f1481a59572f28d97f9c65f5a21676a91dee2ed))
* install with curl, and one process instead of three ([c31b4ee](https://github.com/aburan28/distributed-researcher/commit/c31b4eee7bf0bd47b670c76ae5a7bdbad76a0c1f))
* **mcp:** surface a claim's standing where an agent will actually see it ([51f0720](https://github.com/aburan28/distributed-researcher/commit/51f0720a0f0bf511dfb02af759347593f681f635))
* rename proofwork to cairn ([940e21a](https://github.com/aburan28/distributed-researcher/commit/940e21a943087b04009ce0b44463f91f26c6228c))
* settle on the clock, not on arrival order ([7fbae4b](https://github.com/aburan28/distributed-researcher/commit/7fbae4bef1507540187dc1d8c8175777f9e60bc6))
* settle on the clock, not on arrival order (re-target to main) ([816efa1](https://github.com/aburan28/distributed-researcher/commit/816efa15b1153c7cc62d611cb1ba5a1a5146030a))
* typed claim relations, and a knowledge view nobody has to agree with ([243333f](https://github.com/aburan28/distributed-researcher/commit/243333f1211aa1ec08441fe9904914a0f10550e8))
* typed claim relations, and a knowledge view nobody has to agree with ([eb23ea2](https://github.com/aburan28/distributed-researcher/commit/eb23ea23d4a3bcad367fc57b2c275c96bbd26c00))
* **ui:** a cairn site whose numbers are re-derivable ([acc6e39](https://github.com/aburan28/distributed-researcher/commit/acc6e39e3fc8d00eb41e3af1748e88a1b6acaf7b))


### Fixes

* a retraction needs the target's key, not a matching name ([ec66fee](https://github.com/aburan28/distributed-researcher/commit/ec66fee330ed125c1e95512e2cc2bb0dbc65de9c))
* a retraction needs the target's key, not a matching name ([8ef5751](https://github.com/aburan28/distributed-researcher/commit/8ef575113808a4d54d25e370543d23934c64d877))
* **ci:** scripts/shard-demo.sh and mcp-config.sh lost their +x bit ([4b21d2f](https://github.com/aburan28/distributed-researcher/commit/4b21d2f3c1f8dacd7800216a66cfbf03b0051782))
* **docs:** cargo doc -D warnings fails on main, independent of this branch ([26bb71d](https://github.com/aburan28/distributed-researcher/commit/26bb71d888b1d9037fa0f7cb8508b2a4c5c56d02))
* examples/ecdlp was a bounty whose author knew the answer ([f80b478](https://github.com/aburan28/distributed-researcher/commit/f80b478908ed06a8816c119db19bad614456c861))
* examples/ecdlp was a bounty whose author knew the answer ([906d2e9](https://github.com/aburan28/distributed-researcher/commit/906d2e9fbc8f3f0c91a11996817aad3ed4fd87a7))
* measure a log's epoch length instead of guessing at it ([d40b139](https://github.com/aburan28/distributed-researcher/commit/d40b1392ab9b15513d6910166e25af31d29af8bc))
* measure a log's epoch length instead of guessing at it ([159eb39](https://github.com/aburan28/distributed-researcher/commit/159eb398297d30ac275e5e0551308479575e10ca))
* refuse to settle a log under a changed epoch length ([4aa2148](https://github.com/aburan28/distributed-researcher/commit/4aa214819f43f1d4cf8da64f1fd73f2ef320d8bb))
* refuse to settle a log under a changed epoch length ([7cf0df4](https://github.com/aburan28/distributed-researcher/commit/7cf0df41682b489a5fea7982c4d1daebc9c3eb97))
* **scripts:** wait out the finality delay before settling ([967bafe](https://github.com/aburan28/distributed-researcher/commit/967bafe10c900b65bf680cd57f750d798a7da227))
* serve a sealed log, name the version a dispatch builds, retire a stale warning ([c581cde](https://github.com/aburan28/distributed-researcher/commit/c581cde212bedf7450f11ea5852b61e8def6508f))
* teach the CLI and MCP that an epoch closing is no longer enough ([e4be4f3](https://github.com/aburan28/distributed-researcher/commit/e4be4f3003579724c3134562d1e1f7eadc231367))
* **tests:** two more suites were one epoch short ([de662a7](https://github.com/aburan28/distributed-researcher/commit/de662a78348be3e0bece3ddad68b35eed42c4a4a))
* the CLI and MCP still assume an epoch closing is enough to settle ([8a48057](https://github.com/aburan28/distributed-researcher/commit/8a48057eb7cc6a7e63398fd0f5bfb09ce4eec6ab))
* the rename must not touch wire constants, pinned code, or module names ([812e667](https://github.com/aburan28/distributed-researcher/commit/812e6672119853802050d98164eb3acab601cdfc))


### Documentation

* buy the ILPs an FHE compiler hides, and refuse the compute ([a60920f](https://github.com/aburan28/distributed-researcher/commit/a60920f5fae09565b70e26b2e03287610fbb8c17))
* buy the ILPs an FHE compiler hides, and refuse the compute ([400c874](https://github.com/aburan28/distributed-researcher/commit/400c8741ff5ce59e0cf76c2e6f3c4fd539444810))
* **ci:** name the setting that makes release-please fail at the last step ([5c04058](https://github.com/aburan28/distributed-researcher/commit/5c04058d86685d74433bbfe634a3d51353fd5068))
* design embargo enforcement, and refuse the pairing that would buy it ([a662e78](https://github.com/aburan28/distributed-researcher/commit/a662e785a552a0e1eb6f26e6f636968161b6ae08))
* design embargo enforcement, and refuse the pairing that would buy it ([32bde3f](https://github.com/aburan28/distributed-researcher/commit/32bde3fe607a23df3c4b490a170980fa9d75afc5))
* design repository-shaped objectives, and name the half of Yukon we refuse ([6702657](https://github.com/aburan28/distributed-researcher/commit/6702657bc962875174c852680c6772759d4740e2))
* design repository-shaped objectives, and name the half of Yukon we refuse ([b4ec908](https://github.com/aburan28/distributed-researcher/commit/b4ec90879f85220ab665805e37a6dc109335deb4))
* two checks CI runs that the pre-flight list did not mention ([b182f48](https://github.com/aburan28/distributed-researcher/commit/b182f48f986a40e8c8a854f2427f2a1ec6ef54fd))
* what a proof about verification would buy, and what it would cost ([8e78aa9](https://github.com/aburan28/distributed-researcher/commit/8e78aa93ec782242516f837bf3e6f00557379810))
* what a proof about verification would buy, and what it would cost ([850e8e4](https://github.com/aburan28/distributed-researcher/commit/850e8e4d87d02cd10451ae8156323295bb7474d0))
* what a shared clock would buy, and the priority gap nobody recorded ([048cfa0](https://github.com/aburan28/distributed-researcher/commit/048cfa0a619f390546d71f835190c5e4f10b5a4f))
* what a shared clock would buy, and the priority gap nobody recorded ([b0546cb](https://github.com/aburan28/distributed-researcher/commit/b0546cbb979ffdfe61d4a5c39328dfa860eeffba))
* what erasure coding prices about identity, and what it does not ([f836a92](https://github.com/aburan28/distributed-researcher/commit/f836a92deee091a38504b70b63116ce7e216d310))
* what erasure coding prices about identity, and what it does not ([f6eefbf](https://github.com/aburan28/distributed-researcher/commit/f6eefbf9d30eb8c234f101a70bb827d15e521fa7))
