use assert_cmd::Command;
use httpmock::prelude::*;
use predicates::str::contains;
use std::fs;
use tempfile::tempdir;

fn quiltc_cmd(server: &MockServer) -> Command {
    let mut cmd = Command::cargo_bin("quiltc").expect("quiltc binary");
    cmd.arg("--base-url")
        .arg(server.base_url())
        .arg("--api-key")
        .arg("test-key");
    cmd
}

#[test]
fn k8s_apply_uses_manifest_string_contract() {
    let server = MockServer::start();
    let tmp = tempdir().expect("tempdir");
    let f = tmp.path().join("app.yaml");
    fs::write(
        &f,
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n",
    )
    .expect("write");

    let validate = server.mock(|when, then| {
        when.method(POST)
            .path("/api/k8s/validate")
            .json_body_obj(&serde_json::json!({
                "manifest":"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n",
                "namespace": null,
                "strict": false
            }));
        then.status(200)
            .json_body_obj(&serde_json::json!({"valid":true,"warnings":[],"errors":[]}));
    });
    let apply = server.mock(|when, then| {
        when.method(POST)
            .path("/api/k8s/apply")
            .json_body_obj(&serde_json::json!({
                "manifest":"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n",
                "cluster_id":"cluster-a",
                "application":"default",
                "namespace": null,
                "strict": false,
                "dry_run": false,
                "prune": false
            }));
        then.status(200).json_body_obj(&serde_json::json!({
            "operation_id":"op-1",
            "status":"accepted",
            "summary":{"cluster_id":"cluster-a","application":"default","created":1,"updated":0,"deleted":0,"unchanged":0},
            "warnings":[],
            "errors":[],
            "diff":[]
        }));
    });

    quiltc_cmd(&server)
        .args([
            "k8s",
            "apply",
            "-f",
            f.to_str().expect("path"),
            "--cluster-id",
            "cluster-a",
        ])
        .assert()
        .success()
        .stdout(contains("operation_id: op-1"));

    validate.assert();
    apply.assert();
}

#[test]
fn k8s_apply_dry_run_calls_diff_with_cluster_scope() {
    let server = MockServer::start();
    let tmp = tempdir().expect("tempdir");
    let f = tmp.path().join("app.yaml");
    fs::write(
        &f,
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n",
    )
    .expect("write");

    let validate = server.mock(|when, then| {
        when.method(POST).path("/api/k8s/validate");
        then.status(200)
            .json_body_obj(&serde_json::json!({"valid":true,"warnings":[],"errors":[]}));
    });
    let diff = server.mock(|when, then| {
        when.method(POST)
            .path("/api/k8s/diff")
            .json_body_obj(&serde_json::json!({
                "manifest":"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n",
                "cluster_id":"cluster-a",
                "application":"default",
                "namespace": null,
                "strict": false
            }));
        then.status(200).json_body_obj(&serde_json::json!({
            "cluster_id":"cluster-a",
            "application":"default",
            "warnings":[],
            "errors":[],
            "diff":[]
        }));
    });
    let apply = server.mock(|when, then| {
        when.method(POST).path("/api/k8s/apply");
        then.status(200)
            .json_body_obj(&serde_json::json!({"operation_id":"op-never"}));
    });

    quiltc_cmd(&server)
        .args([
            "k8s",
            "apply",
            "-f",
            f.to_str().expect("path"),
            "--cluster-id",
            "cluster-a",
            "--dry-run",
        ])
        .assert()
        .success();

    validate.assert();
    diff.assert();
    assert_eq!(apply.hits(), 0, "apply must not run in dry-run mode");
}

#[test]
fn k8s_status_uses_applies_endpoint_with_cluster_id() {
    let server = MockServer::start();
    let status = server.mock(|when, then| {
        when.method(GET)
            .path("/api/k8s/applies/op-1")
            .query_param("cluster_id", "cluster-a");
        then.status(200).json_body_obj(&serde_json::json!({
            "operation_id":"op-1",
            "status":"succeeded",
            "cluster_id":"cluster-a",
            "application":"default",
            "warnings":[],
            "errors":[]
        }));
    });

    quiltc_cmd(&server)
        .args([
            "k8s",
            "status",
            "--operation",
            "op-1",
            "--cluster-id",
            "cluster-a",
        ])
        .assert()
        .success();

    status.assert();
}

#[test]
fn k8s_apply_follow_failed_maps_to_apply_failure_exit_code() {
    let server = MockServer::start();
    let tmp = tempdir().expect("tempdir");
    let f = tmp.path().join("apply.yaml");
    fs::write(
        &f,
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: apply\n",
    )
    .expect("write");

    let validate = server.mock(|when, then| {
        when.method(POST).path("/api/k8s/validate");
        then.status(200)
            .json_body_obj(&serde_json::json!({"valid":true,"warnings":[],"errors":[]}));
    });
    let apply = server.mock(|when, then| {
        when.method(POST).path("/api/k8s/apply");
        then.status(200).json_body_obj(&serde_json::json!({
            "operation_id":"op-fail",
            "status":"accepted",
            "warnings":[],
            "errors":[]
        }));
    });
    let op_status = server.mock(|when, then| {
        when.method(GET)
            .path("/api/k8s/applies/op-fail")
            .query_param("cluster_id", "cluster-a");
        then.status(200).json_body_obj(&serde_json::json!({
            "operation_id":"op-fail",
            "status":"failed",
            "cluster_id":"cluster-a",
            "application":"default",
            "warnings":[],
            "errors":[]
        }));
    });

    quiltc_cmd(&server)
        .args([
            "k8s",
            "apply",
            "-f",
            f.to_str().expect("path"),
            "--cluster-id",
            "cluster-a",
            "--follow",
            "--timeout-secs",
            "1",
        ])
        .assert()
        .code(3)
        .stderr(contains("operation op-fail terminated with failure"));

    validate.assert();
    apply.assert();
    op_status.assert();
}

#[test]
fn k8s_validate_directory_collection_is_deterministic_manifest_string() {
    let server = MockServer::start();
    let tmp = tempdir().expect("tempdir");
    let sub = tmp.path().join("nested");
    fs::create_dir_all(&sub).expect("mkdir");
    let a = tmp.path().join("a.yaml");
    let b = sub.join("b.yaml");
    fs::write(
        &a,
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n",
    )
    .expect("write a");
    fs::write(
        &b,
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: b\n",
    )
    .expect("write b");

    let validate = server.mock(|when, then| {
        when.method(POST)
            .path("/api/k8s/validate")
            .json_body_obj(&serde_json::json!({
                "manifest":"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: b\n",
                "namespace": null,
                "strict": false
            }));
        then.status(200)
            .json_body_obj(&serde_json::json!({"valid":true,"warnings":[],"errors":[]}));
    });

    quiltc_cmd(&server)
        .args(["k8s", "validate", "-f", tmp.path().to_str().expect("path")])
        .assert()
        .success();

    validate.assert();
}

#[test]
fn k8s_resources_list_and_resource_delete_use_cluster_scope() {
    let server = MockServer::start();
    let list = server.mock(|when, then| {
        when.method(GET)
            .path("/api/k8s/resources")
            .query_param("cluster_id", "cluster-a")
            .query_param("application", "app-a")
            .query_param("kind", "Deployment")
            .query_param("include_secrets", "true");
        then.status(200)
            .json_body_obj(&serde_json::json!({"resources":[]}));
    });
    let get_one = server.mock(|when, then| {
        when.method(GET)
            .path("/api/k8s/resources/res-1")
            .query_param("cluster_id", "cluster-a");
        then.status(200).json_body_obj(&serde_json::json!({
            "resource":{"id":"res-1"},
            "normalized_spec":{"kind":"Deployment"},
            "raw_manifest":"apiVersion: apps/v1"
        }));
    });
    let delete = server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/k8s/resources/res-1")
            .query_param("cluster_id", "cluster-a");
        then.status(204);
    });

    quiltc_cmd(&server)
        .args([
            "k8s",
            "get",
            "resources",
            "--cluster-id",
            "cluster-a",
            "--application",
            "app-a",
            "--kind",
            "Deployment",
            "--include-secrets",
            "true",
        ])
        .assert()
        .success();

    quiltc_cmd(&server)
        .args([
            "k8s",
            "get",
            "resource",
            "res-1",
            "--cluster-id",
            "cluster-a",
        ])
        .assert()
        .success();

    quiltc_cmd(&server)
        .args(["k8s", "delete", "res-1", "--cluster-id", "cluster-a"])
        .assert()
        .success()
        .stdout(contains("\"deleted\":true"));

    list.assert();
    get_one.assert();
    delete.assert();
}

#[test]
fn k8s_export_uses_post_body_contract() {
    let server = MockServer::start();
    let export = server.mock(|when, then| {
        when.method(POST)
            .path("/api/k8s/export")
            .json_body_obj(&serde_json::json!({
                "cluster_id":"cluster-a",
                "application":"default",
                "format":"yaml"
            }));
        then.status(200).json_body_obj(&serde_json::json!({
            "format":"yaml",
            "documents":[],
            "output":"apiVersion: v1\nkind: List\nitems: []\n"
        }));
    });

    quiltc_cmd(&server)
        .args(["k8s", "export", "--cluster-id", "cluster-a", "-o", "yaml"])
        .assert()
        .success()
        .stdout(contains("apiVersion: v1"));

    export.assert();
}

#[test]
fn k8s_validate_auth_failure_maps_to_transport_auth_exit_code() {
    let server = MockServer::start();
    let tmp = tempdir().expect("tempdir");
    let f = tmp.path().join("auth.yaml");
    fs::write(
        &f,
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: auth\n",
    )
    .expect("write");

    let validate = server.mock(|when, then| {
        when.method(POST).path("/api/k8s/validate");
        then.status(401).json_body_obj(&serde_json::json!({
            "error":"unauthorized",
            "error_code":"UNAUTHORIZED"
        }));
    });

    quiltc_cmd(&server)
        .args(["k8s", "validate", "-f", f.to_str().expect("path")])
        .assert()
        .code(4)
        .stderr(contains("status=401"));

    validate.assert();
}
