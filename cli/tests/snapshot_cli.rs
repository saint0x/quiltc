use assert_cmd::Command;
use httpmock::prelude::*;
use predicates::str::contains;

fn quiltc_cmd(server: &MockServer) -> Command {
    let mut cmd = Command::cargo_bin("quiltc").expect("quiltc binary");
    cmd.arg("--base-url")
        .arg(server.base_url())
        .arg("--api-key")
        .arg("test-key");
    cmd
}

#[test]
fn container_snapshot_waits_and_succeeds() {
    let server = MockServer::start();

    let create = server.mock(|when, then| {
        when.method(POST)
            .path("/api/containers/c1/snapshot")
            .header_exists("idempotency-key");
        then.status(200).json_body_obj(&serde_json::json!({
            "operation_id": "op-1",
            "status": "accepted"
        }));
    });

    let get = server.mock(|when, then| {
        when.method(GET).path("/api/operations/op-1");
        then.status(200).json_body_obj(&serde_json::json!({
            "operation_id": "op-1",
            "status": "succeeded",
            "snapshot_id": "snap-1"
        }));
    });

    quiltc_cmd(&server)
        .args([
            "containers",
            "snapshot",
            "c1",
            "--wait",
            "--timeout-secs",
            "2",
        ])
        .assert()
        .success()
        .stdout(contains("\"operation_id\": \"op-1\""))
        .stdout(contains("\"status\": \"succeeded\""));

    create.assert();
    get.assert();
}

#[test]
fn snapshots_list_get_and_lineage_routes() {
    let server = MockServer::start();
    let list = server.mock(|when, then| {
        when.method(GET)
            .path("/api/snapshots")
            .query_param("container_id", "c1")
            .query_param("label", "team=core");
        then.status(200).json_body_obj(&serde_json::json!({"snapshots":[]}));
    });
    let get = server.mock(|when, then| {
        when.method(GET).path("/api/snapshots/s1");
        then.status(200)
            .json_body_obj(&serde_json::json!({"id":"s1","pinned":false}));
    });
    let lineage = server.mock(|when, then| {
        when.method(GET).path("/api/snapshots/s1/lineage");
        then.status(200).json_body_obj(&serde_json::json!({"nodes":[]}));
    });

    quiltc_cmd(&server)
        .args([
            "snapshots",
            "list",
            "--container-id",
            "c1",
            "--label",
            "team=core",
        ])
        .assert()
        .success();
    quiltc_cmd(&server)
        .args(["snapshots", "get", "s1"])
        .assert()
        .success();
    quiltc_cmd(&server)
        .args(["snapshots", "lineage", "s1"])
        .assert()
        .success();

    list.assert();
    get.assert();
    lineage.assert();
}

#[test]
fn snapshot_mutations_use_operation_contract() {
    let server = MockServer::start();
    let delete = server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/snapshots/s1")
            .header_exists("idempotency-key");
        then.status(200).json_body_obj(&serde_json::json!({"operation_id":"op-del"}));
    });
    let pin = server.mock(|when, then| {
        when.method(POST)
            .path("/api/snapshots/s1/pin")
            .header_exists("idempotency-key");
        then.status(200).json_body_obj(&serde_json::json!({"operation_id":"op-pin"}));
    });
    let unpin = server.mock(|when, then| {
        when.method(POST)
            .path("/api/snapshots/s1/unpin")
            .header_exists("idempotency-key");
        then.status(200).json_body_obj(&serde_json::json!({"operation_id":"op-unpin"}));
    });
    let clone = server.mock(|when, then| {
        when.method(POST)
            .path("/api/snapshots/s1/clone")
            .header_exists("idempotency-key");
        then.status(200).json_body_obj(&serde_json::json!({"operation_id":"op-clone"}));
    });
    let resume = server.mock(|when, then| {
        when.method(POST)
            .path("/api/containers/c1/resume")
            .header_exists("idempotency-key");
        then.status(200).json_body_obj(&serde_json::json!({"operation_id":"op-resume"}));
    });

    quiltc_cmd(&server)
        .args(["snapshots", "delete", "s1"])
        .assert()
        .success();
    quiltc_cmd(&server)
        .args(["snapshots", "pin", "s1"])
        .assert()
        .success();
    quiltc_cmd(&server)
        .args(["snapshots", "unpin", "s1"])
        .assert()
        .success();
    quiltc_cmd(&server)
        .args(["snapshots", "clone", "s1"])
        .assert()
        .success();
    quiltc_cmd(&server)
        .args(["containers", "resume", "c1"])
        .assert()
        .success();

    delete.assert();
    pin.assert();
    unpin.assert();
    clone.assert();
    resume.assert();
}

#[test]
fn operations_watch_fails_on_terminal_failure() {
    let server = MockServer::start();
    let get = server.mock(|when, then| {
        when.method(GET).path("/api/operations/op-fail");
        then.status(200).json_body_obj(&serde_json::json!({
            "operation_id":"op-fail",
            "status":"failed",
            "reason_code":"SNAPSHOT_NOT_FOUND"
        }));
    });

    quiltc_cmd(&server)
        .args(["operations", "watch", "op-fail", "--timeout-secs", "1"])
        .assert()
        .failure()
        .stderr(contains("operation op-fail terminated with status=failed"));

    get.assert();
}

#[test]
fn operations_get_route() {
    let server = MockServer::start();
    let get = server.mock(|when, then| {
        when.method(GET).path("/api/operations/op-1");
        then.status(200)
            .json_body_obj(&serde_json::json!({"operation_id":"op-1","status":"running"}));
    });

    quiltc_cmd(&server)
        .args(["operations", "get", "op-1"])
        .assert()
        .success()
        .stdout(contains("\"operation_id\": \"op-1\""));

    get.assert();
}

#[test]
fn require_capability_blocks_when_missing() {
    let server = MockServer::start();
    let caps = server.mock(|when, then| {
        when.method(GET).path("/api/clusters/cluster-a/capabilities");
        then.status(200).json_body_obj(&serde_json::json!({
            "capabilities": {"snapshot:create": false}
        }));
    });
    let snapshot_call = server.mock(|when, then| {
        when.method(POST).path("/api/containers/c1/snapshot");
        then.status(200)
            .json_body_obj(&serde_json::json!({"operation_id":"op-should-not-run"}));
    });

    quiltc_cmd(&server)
        .args([
            "containers",
            "snapshot",
            "c1",
            "--cluster-id",
            "cluster-a",
            "--require-capability",
            "snapshot:create",
        ])
        .assert()
        .failure()
        .stderr(contains("UNSUPPORTED_NODE_CAPABILITY"));

    caps.assert();
    assert_eq!(snapshot_call.hits(), 0, "snapshot call should be preflight-blocked");
}
