# quiltc

`quiltc` is Quilt's Kubernetes-like CLI. It drives a desired-state control plane (clusters, nodes, workloads, placements) and a runtime surface (containers, volumes, events) via HTTP.

See:
- `RESULTS.md` for live verification evidence and the exact endpoint coverage.
- `K8S.md` for the Kubernetes parity mapping.

## Build

```bash
cargo build -p quiltc
```

Binary path on macOS (Apple Silicon): `target/aarch64-apple-darwin/debug/quiltc`

## Configuration

`quiltc` reads auth and base URL from flags and/or environment variables:

- `QUILT_BASE_URL` (e.g. `https://backend.quilt.sh`)
- `QUILT_API_KEY` (tenant key, sent as `X-Api-Key`)
- `QUILT_JWT` (tenant JWT, sent as `Authorization: Bearer ...`)

Optional:
- `--save-auth` stores the provided tenant auth in `~/.config/quiltc/config.json` (permissions best-effort `0600` on Unix).

Agent enrollment uses join tokens:
- `QUILT_JOIN_TOKEN` (cluster-scoped, short-lived join token, sent as `X-Quilt-Join-Token` on node registration)

Notes:
- Do not commit secrets. A local `.env` can be used for convenience and is gitignored by this repo.

## Quick Start (Cluster + Nodes + Workload)

Create a cluster:

```bash
quiltc clusters create \\
  --name demo \\
  --pod-cidr 10.70.0.0/16 \\
  --node-cidr-prefix 24
```

Mint a join token:

```bash
quiltc clusters join-token-create <cluster_id> --ttl-secs 600 --max-uses 1
```

Register a node (repeat per node; join tokens are typically single-use):

```bash
quiltc agent register <cluster_id> --join-token <join_token> \\
  --name node-a \\
  --public-ip 203.0.113.10 \\
  --private-ip 10.0.0.10 \\
  --agent-version quiltc-test \\
  --labels-json '{}' \\
  --taints-json '{}' \\
  --bridge-name quilt0 \\
  --dns-port 53 \\
  --egress-limit-mbit 0
```

Heartbeat node to `ready`:

```bash
quiltc agent heartbeat <cluster_id> <node_id> --state ready
```

Create a workload (replicated desired-state):

```bash
quiltc clusters workload-create <cluster_id> \\
  '{\"name\":\"demo\",\"replicas\":3,\"command\":[\"sh\",\"-lc\",\"echo hi; tail -f /dev/null\"],\"memory_limit_mb\":128}'
```

Reconcile + observe placements:

```bash
quiltc clusters reconcile <cluster_id>
quiltc clusters placements <cluster_id>
```

## Runtime Operations (Containers)

Create a container:

```bash
quiltc containers create '{\"name\":\"demo\",\"command\":[\"sh\",\"-lc\",\"echo hi; tail -f /dev/null\"],\"memory_limit_mb\":128}'
```

Exec:

```bash
quiltc containers exec <container_id> -- sh -lc 'id && ip addr && ip route'
```

Logs:

```bash
quiltc containers logs <container_id>
```

Events (SSE):

```bash
quiltc events
```

## Volumes (File Push/Pull)

Upload a file into a volume (JSON + base64 behind the scenes):

```bash
quiltc volumes upload <volume_name> ./local.txt --path /remote.txt
```

Download a file from a volume:

```bash
quiltc volumes download <volume_name> ./out.txt --path /remote.txt
```

Upload/extract a `.tar.gz` archive:

```bash
quiltc volumes archive-upload <volume_name> ./bundle.tar.gz --path / --strip-components 0
```

## Escape Hatch

For new/experimental endpoints not yet wrapped by a subcommand:

```bash
quiltc request GET /api/clusters
quiltc request POST /api/clusters/<cluster_id>/join-tokens --json '{\"ttl_secs\":600,\"max_uses\":1}'
```
