# Project specification

## Objective

Provide one self-hosted control plane for explicitly authorized x86-64, ARM64, ARMv7, Android, and Termux-class workers. Registration, heartbeat/resource updates, work claims, progress, cancellation, completion, and recovery share one authenticated pull plane.

## Invariants

- Workers make outbound polls; the hub never opens an inbound worker shell.
- Commands are argument arrays and run with `shell=False` only after a worker-local executable allowlist accepts them.
- Non-loopback hub binding requires operator-supplied TLS; plain HTTP is loopback-only.
- Bearer tokens are generated into local mode-0600 files and never enter state, results, logs, examples, or command arguments.
- Architecture, capability, RAM reserve, and disk reserve are checked before a claim; rejection reasons remain visible.
- A job has one atomic lease owner. Expired leases requeue with bounded backoff or become dead after the declared attempt limit.
- Inputs and outputs are content-addressed, streamed in bounded chunks, verified by SHA-256 and size, and atomically published.
- On-demand dependencies use worker-local install profiles. The hub can select a profile name but cannot supply installation commands.
- The authority is versioned JSON under `DATA/`, protected by an advisory process lock and atomic replacement.
- `CURRENT.md`, `TO-DO.md`, `DONE.md`, `status.json`, and `status.txt` are generated factual views under `DATA/`.
- No operation provides stealth, credential capture, unauthenticated execution, public-exposure defaults, or private-project behavior.

## Job lifecycle

```text
queued -> active -> completed
   |         |        
   |         +-> cancelled
   |         +-> queued (expired lease, bounded retry)
   |         +-> dead (attempts exhausted)
   +-> cancelled
```

Deterministic command failures become `failed`; only lost/expired leases receive automatic retry. Duplicate completion is rejected.

## Acceptance evidence

- Python compile check passes.
- Ten unit/integration tests pass on supported Python versions.
- The synthetic demo performs real HTTP registration, polling, execution, artifact upload, and completion.
- Offscreen PySide6 construction passes in CI.
- Privacy and secret-shape scan is clean before publication.
