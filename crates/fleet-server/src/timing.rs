//! Timing store and RPC logic.

use fleet_proto::v1::{
    GetJobTimingReply, GetJobTimingRequest, ReportTimingReply, ReportTimingRequest,
};
use tonic::Status;

const NOT_IMPLEMENTED: &str = "job timing is not implemented";

/// Stores the timing a box reports for one job attempt.
///
/// # Errors
/// Returns `UNIMPLEMENTED` until the store is built.
pub fn report_timing(_request: &ReportTimingRequest) -> Result<ReportTimingReply, Status> {
    Err(Status::unimplemented(NOT_IMPLEMENTED))
}

/// Reads the stored timing of one job.
///
/// # Errors
/// Returns `UNIMPLEMENTED` until the store is built.
pub fn get_job_timing(_request: &GetJobTimingRequest) -> Result<GetJobTimingReply, Status> {
    Err(Status::unimplemented(NOT_IMPLEMENTED))
}
