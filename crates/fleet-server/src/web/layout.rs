//! The shared page frame: one place that emits the document skeleton.
//!
//! [`shell`] frames the signed-in pages with the sidebar. [`bare`] frames the public pages
//! with a centred card. Both put `data-mode` and `data-csrf` on `<main id="app">`, where
//! `passkey.js` reads them. Every class is a literal string so Tailwind finds it.

use topcoat::{
    Result,
    context::Cx,
    view::{Child, View, component, view},
};

use super::pages::{NAV_SCRIPT_PATH, STYLE_PATH, auth, current, fail};

/// The sidebar entry a page marks as current.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Nav {
    Jobs,
    Profiles,
    Tokens,
    BoxTokens,
    Credentials,
    Environments,
    Hosts,
    Repos,
    Work,
    Pitfalls,
    Catalog,
    Account,
}

const NAV_ITEMS: [(Nav, &str, &str); 12] = [
    (Nav::Jobs, "/jobs", "Jobs"),
    (Nav::Profiles, "/profiles", "Profiles"),
    (Nav::Tokens, "/tokens", "Tokens"),
    (Nav::BoxTokens, "/box-tokens", "Box tokens"),
    (Nav::Credentials, "/credentials", "Credentials"),
    (Nav::Environments, "/environments", "Environments"),
    (Nav::Hosts, "/hosts", "Git remotes"),
    (Nav::Repos, "/repos", "Repositories"),
    (Nav::Work, "/work", "Work"),
    (Nav::Pitfalls, "/pitfalls", "Pitfalls"),
    (Nav::Catalog, "/catalog", "Catalog"),
    (Nav::Account, "/account", "Account"),
];

/// Whether the viewer is an admin right now: a live `users.is_admin` read, never cached on the
/// session, so a demoted admin loses the Catalog entry on the next request.
async fn viewer_is_admin(cx: &Cx) -> Result<bool> {
    let auth = auth(cx)?;
    match current(cx, auth).await? {
        Some(session) => auth.is_admin(session.user_id).await.map_err(fail),
        None => Ok(false),
    }
}

#[component]
pub(super) async fn shell(
    cx: &Cx,
    title: &str,
    active: Nav,
    user: &str,
    csrf: &str,
    mode: &str,
    child: Child<'_>,
) -> Result<impl View> {
    let admin = viewer_is_admin(cx).await?;
    Ok(view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>(title)</title>
                <link rel="stylesheet" href=(STYLE_PATH)>
                <script src=(NAV_SCRIPT_PATH) defer=""></script>
            </head>
            <body class="bg-base-100 text-base-content">
                <a class="sr-only focus:not-sr-only focus:absolute focus:z-10 focus:bg-base-300 focus:p-2" href="#app">"Skip to content"</a>
                <div class="flex min-h-screen flex-col lg:flex-row">
                    <nav class="hidden lg:flex lg:sticky lg:top-0 lg:h-screen lg:overflow-y-auto lg:w-48 shrink-0 flex-col border-r border-base-300 bg-base-200" aria-label="Main">
                        <ul class="menu menu-sm w-full">
                            <li class="menu-title">"fleet"</li>
                            for item in NAV_ITEMS {
                                if admin || item.0 != Nav::Catalog {
                                    <li>
                                        if item.0 == active {
                                            <a class="menu-active" href=(item.1) aria-current="page">(item.2)</a>
                                        } else {
                                            <a href=(item.1)>(item.2)</a>
                                        }
                                    </li>
                                }
                            }
                        </ul>
                        <div class="mt-auto flex flex-col gap-2 border-t border-base-300 p-2 text-xs">
                            <span class="truncate text-base-content/60">(user)</span>
                            <form method="post" action="/logout">
                                <input type="hidden" name="csrf" value=(csrf)>
                                <button class="btn btn-outline btn-xs w-full" type="submit">"Sign out"</button>
                            </form>
                        </div>
                    </nav>
                    <nav class="nav-fade flex lg:hidden overflow-x-auto scroll-px-8 gap-1 border-b border-base-300 bg-base-200 p-2 text-xs" aria-label="Main mobile">
                        <form class="shrink-0" method="post" action="/logout">
                            <input type="hidden" name="csrf" value=(csrf)>
                            <button class="btn btn-outline btn-xs" type="submit">"Sign out"</button>
                        </form>
                        <ul class="menu menu-sm menu-horizontal flex-nowrap items-center p-0 pe-8">
                            <li class="menu-title">"fleet"</li>
                            for item in NAV_ITEMS {
                                if admin || item.0 != Nav::Catalog {
                                    <li>
                                        if item.0 == active {
                                            <a class="menu-active" href=(item.1) aria-current="page">(item.2)</a>
                                        } else {
                                            <a href=(item.1)>(item.2)</a>
                                        }
                                    </li>
                                }
                            }
                        </ul>
                    </nav>
                    <main id="app" class="min-w-0 flex-1 p-3" data-mode=(mode) data-csrf=(csrf)>
                        (child)
                    </main>
                </div>
            </body>
        </html>
    })
}

#[component]
pub(super) async fn bare(title: &str, mode: &str, child: Child<'_>) -> Result<impl View> {
    Ok(view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>(title)</title>
                <link rel="stylesheet" href=(STYLE_PATH)>
            </head>
            <body class="bg-base-100 text-base-content">
                <a class="sr-only focus:not-sr-only focus:absolute focus:z-10 focus:bg-base-300 focus:p-2" href="#app">"Skip to content"</a>
                <main id="app" class="flex min-h-screen items-center justify-center p-4" data-mode=(mode)>
                    <div class="w-full max-w-sm border border-base-300 bg-base-200 p-4">
                        (child)
                    </div>
                </main>
            </body>
        </html>
    })
}
