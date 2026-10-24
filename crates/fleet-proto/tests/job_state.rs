//! Wire round trips for the job messages.

use fleet_proto::v1::{
    ClaimJobReply, Job, JobState, ReportJobReply, ReportJobRequest, TranscriptChunk,
};
use prost::Message;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn job_state_round_trip() -> TestResult {
    let states = [
        JobState::Queued,
        JobState::Running,
        JobState::Succeeded,
        JobState::Failed,
        JobState::Cancelled,
        JobState::Lost,
    ];
    for state in states {
        let job = Job {
            state: state as i32,
            attempt: 2,
            ..Job::default()
        };
        let decoded = Job::decode(job.encode_to_vec().as_slice())?;
        assert_eq!(decoded.state(), state);
        assert_eq!(decoded.attempt, 2);
    }
    Ok(())
}

#[test]
fn job_state_defaults_to_unspecified() -> TestResult {
    let decoded = Job::decode(Job::default().encode_to_vec().as_slice())?;
    assert_eq!(decoded.state(), JobState::Unspecified);
    assert_eq!(JobState::default(), JobState::Unspecified);
    Ok(())
}

#[test]
fn report_request_round_trip() -> TestResult {
    let request = ReportJobRequest {
        job_id: "j1".into(),
        attempt: 3,
        phase: "pushing".into(),
        branch: Some("swarm/j1".into()),
        exit_code: Some(7),
        pr_url: Some("https://example.test/pr/1".into()),
        terminal_state: Some(JobState::Failed as i32),
        chunks: vec![
            TranscriptChunk {
                seq: 1,
                text: "a".into(),
                ..TranscriptChunk::default()
            },
            TranscriptChunk {
                seq: 2,
                text: "b".into(),
                truncated: true,
                ..TranscriptChunk::default()
            },
        ],
        ..ReportJobRequest::default()
    };
    let decoded = ReportJobRequest::decode(request.encode_to_vec().as_slice())?;
    assert_eq!(decoded, request);
    assert_eq!(decoded.branch.as_deref(), Some("swarm/j1"));
    assert_eq!(decoded.phase, "pushing");
    assert_eq!(decoded.exit_code, Some(7));
    assert_eq!(decoded.chunks.len(), 2);
    Ok(())
}

#[test]
fn report_request_without_branch_decodes_to_none() -> TestResult {
    let decoded = ReportJobRequest::decode(ReportJobRequest::default().encode_to_vec().as_slice())?;
    assert_eq!(decoded.branch, None);
    assert_eq!(decoded.exit_code, None);
    Ok(())
}

#[test]
fn report_reply_round_trip() -> TestResult {
    let reply = ReportJobReply {
        lease_expires_at_ms: 99,
        cancel_requested: true,
        acked_through_seq: 42,
        transcript_truncated: true,
    };
    let decoded = ReportJobReply::decode(reply.encode_to_vec().as_slice())?;
    assert_eq!(decoded, reply);
    assert_eq!(decoded.acked_through_seq, 42);
    assert!(decoded.transcript_truncated);
    Ok(())
}

#[test]
fn claim_reply_without_job_decodes_to_none() -> TestResult {
    let reply = ClaimJobReply {
        job: None,
        lease_s: 0,
        next_in_s: 5,
    };
    let decoded = ClaimJobReply::decode(reply.encode_to_vec().as_slice())?;
    assert!(decoded.job.is_none());
    assert_eq!(decoded.next_in_s, 5);
    Ok(())
}

#[test]
fn job_optional_fields_set_and_unset() -> TestResult {
    let set = Job {
        phase: "running".into(),
        lease_expires_at_ms: Some(1),
        exit_code: Some(0),
        branch: Some("swarm/j".into()),
        pr_url: Some("u".into()),
        error: Some("e".into()),
        claimed_at_ms: Some(2),
        finished_at_ms: Some(3),
        ..Job::default()
    };
    let decoded = Job::decode(set.encode_to_vec().as_slice())?;
    assert_eq!(decoded, set);
    assert_eq!(decoded.phase, "running");
    assert_eq!(decoded.exit_code, Some(0));
    let unset = Job::decode(Job::default().encode_to_vec().as_slice())?;
    assert_eq!(unset.branch, None);
    assert_eq!(unset.exit_code, None);
    assert_eq!(unset.finished_at_ms, None);
    assert_eq!(unset.phase, "");
    Ok(())
}
