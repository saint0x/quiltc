#![allow(dead_code)]

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Snapshot {
    pub id: String,
    pub container_id: Option<String>,
    pub parent_snapshot_id: Option<String>,
    pub created_at: Option<String>,
    pub ttl_seconds: Option<u64>,
    pub labels: Option<BTreeMap<String, String>>,
    pub pinned: Option<bool>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SnapshotLineageNode {
    pub snapshot_id: String,
    pub parent_snapshot_id: Option<String>,
    pub container_id: Option<String>,
    pub created_at: Option<String>,
    pub depth: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LifecycleRequestOptions {
    pub consistency_mode: Option<String>,
    pub network_mode: Option<String>,
    pub volume_mode: Option<String>,
    pub resume_policy: Option<String>,
    pub placement_hint: Option<serde_json::Value>,
    pub ttl_seconds: Option<u64>,
    pub labels: Option<BTreeMap<String, String>>,
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CapabilityMatrix {
    pub cluster_id: Option<String>,
    pub capabilities: Option<BTreeMap<String, bool>>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OperationResponse {
    pub operation_id: Option<String>,
    pub status: Option<OperationStatus>,
    pub snapshot_id: Option<String>,
    pub container_id: Option<String>,
    pub warnings: Option<Vec<String>>,
    pub capability_downgrades: Option<Vec<String>>,
    pub reason_code: Option<String>,
    pub reason_message: Option<String>,
    pub progress_pct: Option<u64>,
    pub started_at: Option<String>,
    pub updated_at: Option<String>,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationStatus {
    Accepted,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Unknown(String),
}

impl<'de> Deserialize<'de> for OperationStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "accepted" => Self::Accepted,
            "running" => Self::Running,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            _ => Self::Unknown(value),
        })
    }
}

impl Serialize for OperationStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl OperationStatus {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Accepted => "accepted",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Unknown(v) => v.as_str(),
        }
    }

    pub fn is_terminal_failure(&self) -> bool {
        matches!(self, Self::Failed | Self::Cancelled)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}
