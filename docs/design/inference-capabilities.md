# Inference capabilities and private research requests

This design adds four useful pieces of provider infrastructure without making
model output authoritative:

1. capability-aware scheduling;
2. content-addressed model manifests;
3. explicit attestation levels; and
4. per-request encrypted envelopes.

The implementation is in `src/compute.rs`. It is intentionally outside the
ledger record and verifier state machines. A model response is a candidate
artifact. It becomes a research result only after a pinned cairn verifier
accepts it and the ordinary immutable log rules settle it.

## Routing contract

Every worker advertises one or more `ModelManifest` values. A manifest binds the
human-facing alias to the family, concrete build, weights digest, tokenizer
digest, and optional template digest. The scheduler requires the exact
`sha256:` digest, not merely the alias.

The scheduler then filters on:

- model-manifest digest;
- minimum memory;
- available concurrency;
- queue-depth ceiling;
- minimum attestation level;
- encrypted-request support; and
- encrypted-response support.

Among eligible workers it chooses the lowest `(queue + active, estimated
latency, worker_id)` tuple. The latency and queue values are routing hints. They
are not proof of execution, billing evidence, or a verifier result.

## Attestation contract

`none < self_signed < hardware < code_identity` is a routing order. The levels
mean only that progressively stronger identity or platform claims were
presented by a worker. They do not prove that:

- the model output is mathematically correct;
- the model followed the request;
- the response is reproducible; or
- the worker performed the claimed amount of useful work.

Those questions remain the responsibility of the pinned verifier and its
independent replay path.

## Request envelope

`RequestEnvelope` uses an ephemeral X25519 sender key and a provider static key,
then derives a request-specific ChaCha20-Poly1305 key. The AEAD binds:

- request id;
- task/objective id; and
- exact model-manifest digest.

Moving a ciphertext to a different request, objective, or model digest fails
authentication. This is transport confidentiality and request binding. It is
not an execution attestation and must not be used as a settlement receipt.

The envelope does not hide traffic size or timing. It also does not prevent a
provider from seeing plaintext while it performs inference; it only prevents
intermediaries from reading the payload. Sensitive research material therefore
needs a separate data-classification and provider-trust decision.

## Provenance required at the adapter boundary

An inference adapter should retain, outside the consensus-critical claim body:

- request id and task/objective id;
- endpoint and worker id;
- selected model-manifest digest and full manifest;
- attestation level and attestation receipt, if any;
- request/response hashes;
- sampling parameters and seed, when supported;
- timestamps and transport outcome; and
- the exact response bytes or a recoverable encrypted archive.

Failures and timeouts are infrastructure outcomes. They are never negative
evidence about the research hypothesis. Remote output is labelled
`agent_proposal` until a local deterministic verifier says otherwise.

## Threat-model additions

The following remain deliberately outside this module:

| Threat | Status | Boundary |
|---|---|---|
| Provider lies about queue or latency | partial | Affects routing only; never settlement. |
| Provider returns a plausible but wrong answer | handled by separation | The pinned verifier, not the provider, decides validity. |
| Model alias moves to a new build | handled | Jobs bind to the manifest digest. |
| Ciphertext replay under another job | handled | Request metadata is AEAD associated data. |
| Provider sees plaintext | explicit residual | The provider is the inference endpoint; use classification and trust policy. |
| Model-output reproducibility | not provided | Requires a model-specific verifier or replay contract. |
