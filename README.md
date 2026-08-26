# Heterogeneous Worker Control Plane

A local-first, authenticated pull control plane for mixed x86-64, ARM64, ARMv7, Android, and Termux workers. It provides resource-aware assignment, real allowlisted execution, SHA-256 artifact/model transfer, worker-approved dependency profiles, progress, cancellation, leases, bounded retries, failure recovery, and factual provenance without Docker, Redis, Kafka, or a paid service.

## One-command desktop setup

```bash
./install.sh
./run.sh
```

`run.sh` automatically repairs incomplete setup and opens the PySide6 control room. The GUI shows real worker resources, queued/active/terminal jobs, phases, attempts and bounded errors; it can start/stop the loopback hub, submit a job file, cancel selected work, refresh state, and run the isolated synthetic demo.

Command-line operation stays in `cli.sh`:

```bash
./cli.sh init
./cli.sh serve                         # 127.0.0.1:8789 by default
./cli.sh submit job.example.json
./cli.sh status
./cli.sh cancel JOB_ID
./cli.sh demo                          # full isolated end-to-end verification
```

The demo does not fake a completion: it creates a temporary hub, registers a synthetic worker over the real HTTP API, claims a resource-gated job, runs an allowlisted Python command without a shell, uploads the declared output by verified SHA-256, and confirms the terminal record.

## Add a worker

On a headless Linux, ARM, Android, or Termux worker:

```bash
./install.sh --worker-only
cp worker-config.example.json worker.json
# edit worker.json, then securely place the hub's DATA/enrollment.token
./cli.sh worker worker.json
```

The worker reports normalized architecture, platform/kernel, package manager, CPU/load, RAM, swap, disk, detected accelerator class, agent version, and explicit capabilities. It accepts no inbound connection. The enrollment token is exchanged once for a worker-specific token stored mode 0600. Tokens are never printed by the application.

For multiple machines, bind the hub beyond loopback only with TLS:

```bash
./cli.sh serve --host LAN_BIND_ADDRESS --tls-cert TLS_CERT_FILE --tls-key TLS_KEY_FILE
```

Workers must use an `https://` URL and may specify a trusted `ca_file`. The server refuses non-loopback plain HTTP. Network routing, firewall rules, certificate creation, and secure token transfer remain explicit operator responsibilities.

## Job schema

`job.example.json` is runnable after the bundled synthetic input is present. Important fields:

- `argv`: bounded argument array; never a shell string.
- `required_architectures`: any of `x86_64`, `arm64`, or `armv7`; empty accepts any normalized architecture.
- `required_capabilities`, `min_ram_mb`, `min_disk_mb`: hard eligibility gates with recorded reasons.
- `inputs`: local `source` plus worker-relative `path`, or a previously stored `sha256` plus `path`.
- `outputs`: required relative path and strict maximum size.
- `timeout_seconds`, `lease_seconds`, `max_attempts`: bounded execution and recovery.
- `install_profiles`: names preapproved in that worker's local configuration.

The local submit command streams each source into the content-addressed cache, verifies SHA-256, strips the manager-only source path, and records only artifact provenance. Worker downloads and result uploads use 1 MiB chunks, verify length and digest, and publish atomically.

## Locally approved dependencies

The hub cannot send a package installation command. A worker operator may define a profile:

```json
"install_profiles": {
  "approved-runtime": {
    "argv": ["pkg", "install", "-y", "python"],
    "timeout_seconds": 600
  }
}
```

The worker advertises `install.approved-runtime`. A matching job may request the profile by name. The exact local argument array is run once without a shell, exit zero is required, and an argument-hash marker makes reruns idempotent. Changing the local command invalidates the marker and requires a new verified run. This is explicit local authorization, not remote arbitrary package installation.

## Durable state and recovery

`DATA/state.json` is the versioned authority. A filesystem lock serializes claims and atomic replacement prevents partial JSON publication. `events.jsonl` records meaningful state changes only. Generated `CURRENT.md`, `TO-DO.md`, `DONE.md`, `status.json`, and `status.txt` make recovery visible after restart.

If a worker disappears, its lease expires. The job requeues with bounded exponential backoff while attempts remain, otherwise it becomes `dead`. Validation and nonzero command exits do not retry forever. Active cancellation is observed through heartbeat/progress polling and terminates only the worker-owned process group.

## Concrete distinction

Mature schedulers such as [Ray](https://github.com/ray-project/ray), [Dask Distributed](https://github.com/dask/distributed), and [Nomad](https://github.com/hashicorp/nomad) cover much larger cluster and workload surfaces. This project is narrower: standard-library core, JSON authority, outbound-only polling, explicit small-device inventory, worker-local executable/install allowlists, architecture-correct eligibility reasons, and hash-proven state transfer suitable for a few personally controlled Linux/Android machines. It does not claim their scale, plugin ecosystem, isolation, or high availability.

## Security and honest limitations

- This is an authorization and evidence layer, not an OS sandbox. An allowlisted executable can still access its worker account's permissions. Use a dedicated low-privilege account or lightweight system container for stronger isolation.
- Job commands must be idempotent because a hard failure after external side effects cannot be rolled back by the hub.
- The JSON authority is intended for one hub process and a modest personal fleet, not multiple active hub replicas or thousands of jobs per second.
- Worker stdout/stderr tails are bounded and redacted before persistence, but job authors should never print secrets.
- Artifacts are generic licensed/user-owned bytes. No model weights, executables, credentials, or private data are bundled.
- Android background-process survival depends on the device and explicit platform permissions.

## Verification

```bash
bash -n install.sh run.sh cli.sh
python3 -m compileall -q hwcp tests
python3 -m unittest discover -s tests -v
python3 -m hwcp.cli demo
```

CI additionally installs PySide6 and constructs the complete control-room window offscreen on Python 3.11 and 3.13. See [PROJECT_SPEC.md](PROJECT_SPEC.md) for invariants and [SUPPORT.md](SUPPORT.md) to fund additional development.
