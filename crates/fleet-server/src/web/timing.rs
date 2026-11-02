//! Timing pages.

use topcoat::{Result, router::StatusCode, router::route};

#[route(GET "/jobs/{job_id}/timing")]
async fn timing_page() -> Result<(StatusCode, &'static str)> {
    Ok((StatusCode::NOT_IMPLEMENTED, "job timing is not implemented"))
}
