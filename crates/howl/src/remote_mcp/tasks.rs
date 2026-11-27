use rmcp::{
    ErrorData, RoleServer,
    model::{
        CallToolResponse, CallToolResult, CreateTaskResult, DetailedTask, ProtocolVersion, Task,
        TaskPayload, TaskStatus,
    },
    service::RequestContext,
};
use serde_json::{Map, Value, json};

use crate::delivery::{IntegrationRun, IntegrationRunState};

pub(crate) fn call_response(
    run: &IntegrationRun,
    context: &RequestContext<RoleServer>,
) -> CallToolResponse {
    let native = is_native_protocol(context)
        && context
            .client_capabilities()
            .is_some_and(|capabilities| capabilities.supports_tasks());
    if native {
        CallToolResponse::Task(CreateTaskResult::new(task(run)))
    } else {
        CallToolResult::structured(run.summary()).into()
    }
}

pub(crate) fn is_native_protocol(context: &RequestContext<RoleServer>) -> bool {
    context
        .protocol_version()
        .is_some_and(|version| version >= ProtocolVersion::V_2026_07_28)
}

pub(crate) fn get_task(run: &IntegrationRun) -> Result<DetailedTask, ErrorData> {
    let payload = match &run.state {
        IntegrationRunState::Working => TaskPayload::Working,
        IntegrationRunState::Cancelled => TaskPayload::Cancelled,
        IntegrationRunState::Failed { reason } => TaskPayload::Failed {
            error: Map::from_iter([
                ("code".into(), json!(-32000)),
                ("message".into(), json!(reason)),
            ]),
        },
        IntegrationRunState::Completed { .. } => {
            let value =
                serde_json::to_value(CallToolResult::structured(run.value())).map_err(|_| {
                    ErrorData::internal_error("Could not encode signed run result", None)
                })?;
            let Value::Object(result) = value else {
                return Err(ErrorData::internal_error("Invalid signed run result", None));
            };
            TaskPayload::Completed { result }
        }
    };
    Ok(DetailedTask::new(task(run), payload))
}

fn task(run: &IntegrationRun) -> Task {
    let status = match run.state {
        IntegrationRunState::Working => TaskStatus::Working,
        IntegrationRunState::Completed { .. } => TaskStatus::Completed,
        IntegrationRunState::Failed { .. } => TaskStatus::Failed,
        IntegrationRunState::Cancelled => TaskStatus::Cancelled,
    };
    let task = Task::new(
        hex::encode(run.id),
        status,
        &run.created_at,
        &run.updated_at,
    );
    if status.is_terminal() {
        task
    } else if run.cancellation_requested {
        task.with_poll_interval_ms(1_000).with_status_message(
            "The gateway stopped retrying delivery. A signed reply may still arrive.",
        )
    } else {
        task.with_poll_interval_ms(1_000)
    }
}

#[cfg(test)]
mod tests {
    use rmcp::model::GetTaskResult;

    use super::*;

    #[test]
    fn native_task_status_keeps_the_standard_tool_result_envelope() {
        let mut run = IntegrationRun {
            id: [1; 32],
            channel: [2; 32],
            peer: [3; 32],
            target: [4; 32],
            message: Some([5; 32]),
            state: IntegrationRunState::Working,
            created_at: "2026-11-27T10:11:12Z".into(),
            updated_at: "2026-11-27T10:11:13Z".into(),
            cancellation_requested: true,
        };
        let working = serde_json::to_value(GetTaskResult::new(get_task(&run).unwrap())).unwrap();
        assert_eq!(working["resultType"], "complete");
        assert_eq!(working["taskId"], hex::encode(run.id));
        assert_eq!(working["status"], "working");
        assert_eq!(working["pollIntervalMs"], 1000);
        assert!(working.get("result").is_none());

        run.state = IntegrationRunState::Completed {
            reply: "final signed reply".into(),
            message: [6; 32],
        };
        let completed = serde_json::to_value(GetTaskResult::new(get_task(&run).unwrap())).unwrap();
        assert_eq!(completed["status"], "completed");
        assert_eq!(completed["result"]["structuredContent"], run.value());
        assert!(run.summary().get("reply").is_none());
        assert!(completed.get("pollIntervalMs").is_none());
    }
}

#[cfg(test)]
mod http_tests;
