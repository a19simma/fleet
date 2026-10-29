//! The Topcoat router and its pages.

use std::sync::Arc;

use topcoat::{
    Result,
    router::{Router, RouterBuilderDiscoverExt, header, page, route},
    view::{View, view},
};

/// Stylesheet compiled into the binary, since Topcoat's `asset!` writes beside the binary.
pub const STYLE_CSS: &str = include_str!("../../assets/style.css");

/// URL path of the embedded stylesheet.
pub const STYLE_PATH: &str = "/static/style.css";

/// Heading rendered by the home page.
pub const HOME_MARKER: &str = "fleet";

#[page("/")]
async fn home() -> Result<impl View> {
    Ok(view! {
        <!DOCTYPE html>
        <html>
            <head>
                <title>"fleet"</title>
                <link rel="stylesheet" href=(STYLE_PATH)>
            </head>
            <body>
                <h1>(HOME_MARKER)</h1>
            </body>
        </html>
    })
}

#[route(GET "/static/style.css")]
async fn style() -> Result<([(header::HeaderName, &'static str); 1], &'static str)> {
    Ok(([(header::CONTENT_TYPE, "text/css")], STYLE_CSS))
}

/// The web side of the server: a shared Topcoat router.
#[derive(Clone)]
pub struct Web {
    router: Arc<Router>,
}

impl Web {
    /// Builds the router from every page and route registered in this crate.
    #[must_use]
    pub fn new() -> Self {
        Self {
            router: Arc::new(Router::builder().discover().build()),
        }
    }

    pub(super) fn router(&self) -> &Router {
        &self.router
    }
}

impl Default for Web {
    fn default() -> Self {
        Self::new()
    }
}
