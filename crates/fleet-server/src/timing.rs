//! Timing store and RPC logic.

use fleet_proto::v1::{
    GetJobTimingReply, GetJobTimingRequest, ReportShellLogReply, ReportShellLogRequest,
    ReportTimingReply, ReportTimingRequest, StreamShellLogChunk, StreamShellLogRequest,
};
use tonic::Status;
use tonic::codegen::BoxStream;

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

/// Stores one live shell log chunk a box reports.
///
/// # Errors
/// Returns `UNIMPLEMENTED` until the store is built.
pub fn report_shell_log(_request: &ReportShellLogRequest) -> Result<ReportShellLogReply, Status> {
    Err(Status::unimplemented(NOT_IMPLEMENTED))
}

/// Streams the stored and live chunks of one shell command.
///
/// # Errors
/// Returns `UNIMPLEMENTED` until the store is built.
pub fn stream_shell_log(
    _request: &StreamShellLogRequest,
) -> Result<BoxStream<StreamShellLogChunk>, Status> {
    Err(Status::unimplemented(NOT_IMPLEMENTED))
}
