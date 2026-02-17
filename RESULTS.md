# Quiltc CLI Live Verification Results

Date: 2026-02-17

This document records a live, production-style verification of the `quiltc` CLI against the Quilt backend HTTP API. The goal is to validate that `quiltc` can act as a cluster/container management CLI by successfully calling the backend control-plane and runtime endpoints (no backend functionality is implemented here).

## Environment

- Backend base URL used: `https://backend.quilt.sh`
- Auth used for most tests: tenant API key via `X-Api-Key` (from local `.env`, not committed)
- Local env handling:
  - Repo-root `.env` exists locally and is gitignored.
  - `.env` file permissions were set to `0600`.

Notes on secrets:
- This report redacts all secret material (API keys, JWTs, node tokens).
- Some backend responses include API key values in JSON; those are not reproduced here.

## Tooling

- CLI binary: `quiltc` (Rust)
- Key env vars:
  - `QUILT_BASE_URL=https://backend.quilt.sh`
  - `QUILT_API_KEY=<REDACTED>`

## Verification Artifacts

Raw captures were written to (local machine only):
- `/tmp/quiltc_live_verify` (earlier run)
- `/tmp/quiltc_live_verify2` (earlier run)
- `/tmp/quiltc_live_verify3` (latest run used for most evidence below)

These captures may contain secret-bearing JSON fields (notably API key creation responses). Do not share them without redaction.

## Results Summary

### PASS (works with `X-Api-Key`)

- Health
  - `GET /health` returned 200.

- Containers (runtime)
  - `GET /api/containers` (list)
  - `POST /api/containers` (create)
  - `GET /api/containers/:id` (get)
  - `GET /api/containers/:id/logs` (logs)
  - `POST /api/containers/:id/exec` (exec)
  - `GET /api/containers/:id/network` (network get)
  - `GET /api/containers/:id/metrics` (metrics)
  - `POST /api/containers/:id/stop` (stop)
  - `POST /api/containers/:id/start` (start)
  - `POST /api/containers/:id/kill` (kill)
  - `DELETE /api/containers/:id` (delete)

- Container route injection (tenant-safe, container netns only)
  - `POST /api/containers/:id/routes` (route add)
  - `DELETE /api/containers/:id/routes` (route del)

- Events (SSE)
  - `GET /api/events` streamed events (e.g. `container_update`, `process_monitor_update`).

- API keys
  - `GET /api/api-keys` (list)
  - `POST /api/api-keys` (create)
  - `DELETE /api/api-keys/:id` (delete)

- Volumes (partial)
  - `GET /api/volumes` (list)
  - `POST /api/volumes` (create)
  - `GET /api/volumes/:name` (get)
  - `DELETE /api/volumes/:name` (delete)

### FAIL / BLOCKED (observed auth mismatch)

Some endpoints appear to require a tenant JWT in the `Authorization: Bearer ...` header and reject `X-Api-Key` even when other endpoints accept it.

- Clusters
  - `GET /api/clusters` returned `401` with error `Missing or invalid Authorization header` when called using `X-Api-Key`.
  - Evidence: `/tmp/quiltc_live_verify3/clusters_list.err`

- Volume upload/download
  - `POST /api/volumes/:name/upload` returned `401` `Missing or invalid Authorization header` when called using `X-Api-Key`.
  - `GET /api/volumes/:name/download` returned `401` `Missing or invalid Authorization header` when called using `X-Api-Key`.
  - Evidence: `/tmp/quiltc_live_verify3/volume_upload.err`, `/tmp/quiltc_live_verify3/volume_download.err`

Interpretation:
- Either these endpoints are mounted behind JWT-only middleware, or they explicitly validate `Authorization` rather than accepting `X-Api-Key`.
- From a production CLI standpoint, this is fine if the intended contract is "clusters + volume upload/download require JWT"; otherwise it is a backend auth consistency bug.

## Evidence (Redacted)

### Health

- Request: `GET https://backend.quilt.sh/health`
- Evidence files: `/tmp/quiltc_live_verify3/health.headers`, `/tmp/quiltc_live_verify3/health.body`

### Containers

- Create response (example fields):
  - `container_id`: `<UUID>`
  - `ip_address`: `10.42.0.x` (allocated)
- Evidence files:
  - Create: `/tmp/quiltc_live_verify3/container_create.json`
  - Exec output: `/tmp/quiltc_live_verify3/container_exec.json`
  - Logs: `/tmp/quiltc_live_verify3/container_logs.txt`
  - Metrics: `/tmp/quiltc_live_verify3/container_metrics.json`
  - Network: `/tmp/quiltc_live_verify3/container_network.json`
  - Delete: `/tmp/quiltc_live_verify3/container_delete.json`

### Route Injection

- Route add succeeded:
  - `{ "success": true, "message": "Route 10.96.0.0/16 injected inside container network namespace" }`
- Route del succeeded:
  - `{ "success": true, "message": "Route 10.96.0.0/16 removed inside container network namespace" }`
- Evidence files:
  - `/tmp/quiltc_live_verify3/route_add.json`
  - `/tmp/quiltc_live_verify3/route_del.json`

### Events (SSE)

- Stream contained events including `container_update` and `process_monitor_update`.
- Evidence file:
  - `/tmp/quiltc_live_verify3/events.txt` (large)

### API Keys

- `POST /api/api-keys` succeeded and returned an object including an `id` and a generated `key`.
  - The returned `key` value is a secret and is not included here.
- Evidence files:
  - List: `/tmp/quiltc_live_verify3/api_keys_list.json` (contains secret values; do not share unredacted)
  - Create: `/tmp/quiltc_live_verify3/api_key_create.json` (contains a secret key; do not share unredacted)
  - Delete: `/tmp/quiltc_live_verify3/api_key_delete.json`

### Volumes

- Create/list/get/delete all succeeded using `X-Api-Key`.
- Upload/download failed with 401 as described above.
- Evidence files:
  - Create: `/tmp/quiltc_live_verify3/volume_create.json`
  - List: `/tmp/quiltc_live_verify3/volumes_list.json`
  - Get: `/tmp/quiltc_live_verify3/volume_get.json`
  - Delete: `/tmp/quiltc_live_verify3/volume_delete.json`
  - Upload fail: `/tmp/quiltc_live_verify3/volume_upload.err`
  - Download fail: `/tmp/quiltc_live_verify3/volume_download.err`

## Conclusion

- `quiltc` is able to manage containers end-to-end (create, inspect, exec, logs, metrics, network, routes, lifecycle actions, delete) against `https://backend.quilt.sh` using a tenant API key.
- `quiltc` can stream tenant events via SSE.
- `quiltc` can manage API keys and basic volume lifecycle with an API key.
- Cluster control-plane endpoints and volume upload/download appear to require JWT (Authorization header) rather than accepting API keys, which blocks API-key-only workflows for those surfaces.

## Next Actions

1. Decide the intended production auth contract:
   - Option A: Require JWT for clusters + volume upload/download and document it.
   - Option B: Fix backend to accept `X-Api-Key` consistently on those endpoints.

2. If JWT is required for clusters, perform a follow-up verification run using:
   - `quiltc auth login ...` then `quiltc clusters ...`
   - `quiltc volumes upload/download ...`

