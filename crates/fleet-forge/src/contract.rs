//! The contract harness of ADR-0068: one case table, run against an adapter and the fake server
//! of its forge shape.
//!
//! A [`Case`] is a scenario name shared by both fakes plus an expected [`Outcome`]. [`run_contract`]
//! arms the fake, lets a [`Subject`] act, and returns a [`Report`]. The report is red when the
//! fake lacks the case, the subject lacks the case, the outcome differs, the request count
//! differs, an `Authorization` header was replayed after a redirect, or the outcome text holds
//! the token.

use std::fmt;
use std::future::Future;

use fleet_core::forge::CiResult;
use fleet_core::host::{HostKind, HostName};

use crate::fake::{Fake, Shape};
use crate::{
    CheckState, CiCheck, Credential, ForgeApi, ForgeError, ForgeGit, Permission, PushTarget,
    RepoAccess, RepoRef, Token,
};

/// Which operation a case drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `ForgeApi::identify`.
    Identify,
    /// `ForgeApi::verify`.
    Verify,
    /// `ForgeApi::create_pr`.
    CreatePr,
    /// `ForgeApi::ci_result`.
    CiResult,
    /// `ForgeApi::ci_checks`.
    CiChecks,
    /// `ForgeGit::push`.
    Push,
    /// `ForgeGit::fetch`.
    Fetch,
}

macro_rules! cases {
    ($($variant:ident => ($name:literal, $op:ident, $calls:ident)),+ $(,)?) => {
        /// One scenario of the ADR-0068 contract table. Both fakes answer it by this name.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Case {
            $(
                #[doc = $name]
                $variant,
            )+
        }

        impl Case {
            /// Every case, in table order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The scenario name both fakes share.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self { $(Self::$variant => $name),+ }
            }

            /// The operation the case drives.
            #[must_use]
            pub const fn op(self) -> Op {
                match self { $(Self::$variant => Op::$op),+ }
            }

            /// How many requests the case allows.
            #[must_use]
            pub const fn calls(self) -> Calls {
                match self { $(Self::$variant => Calls::$calls),+ }
            }
        }
    };
}

cases! {
    IdentifyOk => ("identify-ok", Identify, Any),
    IdentifyNonForge => ("identify-non-forge", Identify, Any),
    IdentifyWrongKind => ("identify-wrong-kind", Identify, Any),
    VerifyReadPush => ("verify-read-push", Verify, Any),
    VerifyReadOnly => ("verify-read-only", Verify, Any),
    VerifyNoPermissions => ("verify-no-permissions", Verify, Any),
    Verify404 => ("verify-404", Verify, Any),
    Verify401 => ("verify-401", Verify, Any),
    Verify403 => ("verify-403", Verify, Any),
    Verify5xx => ("verify-5xx", Verify, Any),
    VerifyReset => ("verify-reset", Verify, Any),
    VerifySlow => ("verify-slow", Verify, Any),
    VerifyOverCap => ("verify-over-cap", Verify, Any),
    VerifyRedirect => ("verify-redirect", Verify, One),
    CreatePrOk => ("create-pr-ok", CreatePr, Any),
    CreatePrExists => ("create-pr-exists", CreatePr, Any),
    CreatePrRejected => ("create-pr-rejected", CreatePr, Any),
    CiPending => ("ci-pending", CiResult, Any),
    CiSuccess => ("ci-success", CiResult, Any),
    CiFailure => ("ci-failure", CiResult, Any),
    CiNone => ("ci-none", CiResult, Any),
    CiMixed => ("ci-mixed", CiResult, Any),
    Ci404 => ("ci-404", CiResult, Any),
    CiChecksMixed => ("ci-checks-mixed", CiChecks, Any),
    CiChecksNone => ("ci-checks-none", CiChecks, Any),
    CiChecks404 => ("ci-checks-404", CiChecks, Any),
    CiChecksBadName => ("ci-checks-bad-name", CiChecks, Any),
    CiChecksOverCap => ("ci-checks-over-cap", CiChecks, Any),
    PushOk => ("push-ok", Push, Any),
    PushNonFastForward => ("push-non-fast-forward", Push, Any),
    PushRevoked => ("push-revoked", Push, Any),
    FetchOk => ("fetch-ok", Fetch, Any),
    FetchAuthFailure => ("fetch-auth-failure", Fetch, Any),
    CredentialOtherHost => ("credential-other-host", Verify, None),
    RedactedError => ("redacted-error", Verify, Any),
}

/// How many requests, HTTP and git together, a case allows the subject to make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Calls {
    /// No request: the subject refuses before it sends anything.
    None,
    /// Exactly one request: the subject stops at the first reply.
    One,
    /// At least one request.
    Any,
}

impl Calls {
    const fn allows(self, count: usize) -> bool {
        match self {
            Self::None => count == 0,
            Self::One => count == 1,
            Self::Any => count >= 1,
        }
    }
}

/// The result of driving one case, in the vocabulary both adapters share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// `identify` returned this kind.
    Identified(HostKind),
    /// `verify` succeeded with this push permission.
    Verified(Permission),
    /// `create_pr` returned the URL the fake serves.
    PrUrl,
    /// `create_pr` returned another URL than the fake serves.
    BadUrl,
    /// `ci_result` returned this result.
    Ci(CiResult),
    /// `ci_checks` returned this list.
    Checks(ChecksSeen),
    /// `push` succeeded.
    Pushed,
    /// `fetch` succeeded.
    Fetched,
    /// The operation failed with this error.
    Failed(ForgeError),
}

/// What `ci_checks` returned, compared against the list the fake serves for `ci-checks-mixed`:
/// `build` passed, `lint` failed, a second `build` is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksSeen {
    /// Exactly the three checks of `ci-checks-mixed`, in that order.
    Mixed,
    /// No check.
    Empty,
    /// Any other list.
    Other,
}

impl ChecksSeen {
    fn of(list: &[CiCheck]) -> Self {
        let mixed = [
            ("build", CheckState::Success),
            ("lint", CheckState::Failed),
            ("build", CheckState::Running),
        ];
        let is_mixed = list.len() == mixed.len()
            && list
                .iter()
                .zip(mixed)
                .all(|(check, (name, state))| check.name() == name && check.state() == state);
        if is_mixed {
            Self::Mixed
        } else if list.is_empty() {
            Self::Empty
        } else {
            Self::Other
        }
    }
}

/// What driving one case produced: the [`Outcome`] and every free-text string the adapter
/// returned, which the harness scans for the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Driven {
    /// The outcome.
    pub outcome: Outcome,
    /// The status line of a successful `push` or `fetch`, or the text of the error.
    pub text: String,
}

impl From<Outcome> for Driven {
    fn from(outcome: Outcome) -> Self {
        Self {
            outcome,
            text: String::new(),
        }
    }
}

impl Case {
    /// The outcome both adapters owe on a fake of `shape`.
    ///
    /// `create_pr` on an existing pull request returns the existing URL, the stricter of the two
    /// ADR readings. `ci-mixed` holds a success, a failure and a pending check and owes
    /// `Failure`. `Queued` and `Neutral` have no case because a Gitea commit status cannot
    /// express them.
    #[must_use]
    pub const fn expected(self, shape: Shape) -> Outcome {
        use ForgeError::{
            HostMismatch, Malformed, NonFastForward, NotFound, Redirected, Timeout, TooLarge,
            Unauthorized, Unavailable, WrongKind,
        };
        match self {
            Self::IdentifyOk => Outcome::Identified(shape.kind()),
            Self::IdentifyNonForge | Self::IdentifyWrongKind => Outcome::Failed(WrongKind),
            Self::VerifyReadPush => Outcome::Verified(Permission::Granted),
            Self::VerifyReadOnly => Outcome::Verified(Permission::Denied),
            Self::VerifyNoPermissions => Outcome::Verified(Permission::Unknown),
            Self::Verify404
            | Self::Verify401
            | Self::Verify403
            | Self::Ci404
            | Self::CiChecks404 => Outcome::Failed(NotFound),
            Self::Verify5xx | Self::VerifyReset | Self::RedactedError => {
                Outcome::Failed(Unavailable)
            }
            Self::VerifySlow => Outcome::Failed(Timeout),
            Self::VerifyOverCap => Outcome::Failed(TooLarge),
            Self::VerifyRedirect => Outcome::Failed(Redirected),
            Self::CreatePrOk | Self::CreatePrExists => Outcome::PrUrl,
            Self::CreatePrRejected => Outcome::Failed(ForgeError::Rejected),
            Self::CiPending => Outcome::Ci(CiResult::InProgress),
            Self::CiSuccess => Outcome::Ci(CiResult::Success),
            Self::CiFailure | Self::CiMixed => Outcome::Ci(CiResult::Failure),
            Self::CiNone => Outcome::Ci(CiResult::NoChecks),
            Self::CiChecksMixed => Outcome::Checks(ChecksSeen::Mixed),
            Self::CiChecksNone => Outcome::Checks(ChecksSeen::Empty),
            Self::CiChecksBadName | Self::CiChecksOverCap => Outcome::Failed(Malformed),
            Self::PushOk => Outcome::Pushed,
            Self::PushNonFastForward => Outcome::Failed(NonFastForward),
            Self::PushRevoked | Self::FetchAuthFailure => Outcome::Failed(Unauthorized),
            Self::FetchOk => Outcome::Fetched,
            Self::CredentialOtherHost => Outcome::Failed(HostMismatch),
        }
    }
}

/// What acts on a case: an adapter, or a stub in the harness self-test.
pub trait Subject: Sync {
    /// Drives `case` against the armed `fake`. `None` means the subject has no code for the
    /// case, which the harness reports as a missing case.
    fn run(&self, case: Case, fake: &Fake) -> impl Future<Output = Option<Driven>> + Send;
}

/// A [`Subject`] built from an adapter factory. It lacks no case: every case drives the
/// adapter through [`drive`].
#[derive(Debug)]
pub struct AdapterSubject<F>(pub F);

impl<A, F> Subject for AdapterSubject<F>
where
    A: ForgeApi + ForgeGit,
    F: Fn(&Fake) -> A + Sync,
{
    async fn run(&self, case: Case, fake: &Fake) -> Option<Driven> {
        let adapter = (self.0)(fake);
        Some(drive(&adapter, case, fake).await)
    }
}

const OTHER_HOST: &str = "other.example.com";

fn host(text: &str) -> HostName {
    HostName::normalise(text).unwrap_or_else(|_| unreachable_host())
}

#[expect(
    clippy::panic,
    reason = "the fixture hosts are literals that normalise, so this cannot run"
)]
fn unreachable_host() -> HostName {
    panic!("fixture host does not normalise")
}

#[expect(
    clippy::panic,
    reason = "the fixture token is a literal that validates, so this cannot run"
)]
fn fixture_token() -> Token {
    Token::new(Fake::TOKEN.to_owned()).unwrap_or_else(|_| panic!("fixture token invalid"))
}

#[expect(
    clippy::panic,
    reason = "the fixture repository is a literal that validates, so this cannot run"
)]
fn fixture_access(fake: &Fake, credential_host: &str) -> RepoAccess {
    let repo = RepoRef::new(fake.host(), "octo", "widgets")
        .unwrap_or_else(|_| panic!("fixture repo invalid"));
    RepoAccess::new(
        repo,
        Credential::new(host(credential_host), fixture_token()),
    )
}

#[expect(
    clippy::panic,
    reason = "the fixture target is a literal that validates, so this cannot run"
)]
fn fixture_target(access: RepoAccess) -> PushTarget {
    PushTarget::new(access, "fleet/job-1", "main")
        .unwrap_or_else(|_| panic!("fixture target invalid"))
}

fn failed<T>(result: Result<T, ForgeError>, ok: impl FnOnce(T) -> Driven) -> Driven {
    match result {
        Ok(value) => ok(value),
        Err(error) => Driven {
            outcome: Outcome::Failed(error),
            text: error.to_string(),
        },
    }
}

fn plain(outcome: Outcome) -> Driven {
    outcome.into()
}

/// Drives `case` through the adapter traits and maps the result to a [`Driven`].
///
/// The fixture repository is `octo/widgets` on the fake's host. `credential-other-host` pairs it
/// with a credential stored for another host.
pub async fn drive<A: ForgeApi + ForgeGit>(adapter: &A, case: Case, fake: &Fake) -> Driven {
    let own_host = fake.host();
    let credential_host = if matches!(case, Case::CredentialOtherHost) {
        OTHER_HOST
    } else {
        own_host.as_str()
    };
    let access = fixture_access(fake, credential_host);
    match case.op() {
        Op::Identify => failed(adapter.identify(&fake.host()).await, |kind| {
            plain(Outcome::Identified(kind))
        }),
        Op::Verify => failed(adapter.verify(&access).await, |v| {
            plain(Outcome::Verified(v.push))
        }),
        Op::CreatePr => {
            let target = fixture_target(access);
            failed(adapter.create_pr(&target, "title", "body").await, |url| {
                plain(if url == fake.pr_url() {
                    Outcome::PrUrl
                } else {
                    Outcome::BadUrl
                })
            })
        }
        Op::CiResult => {
            let target = fixture_target(access);
            failed(adapter.ci_result(&target, &fake.pr_url()).await, |ci| {
                plain(Outcome::Ci(ci))
            })
        }
        Op::CiChecks => {
            let target = fixture_target(access);
            failed(adapter.ci_checks(&target, &fake.pr_url()).await, |list| {
                plain(Outcome::Checks(ChecksSeen::of(&list)))
            })
        }
        Op::Push => {
            let target = fixture_target(access);
            failed(adapter.push(&target).await, |text| Driven {
                outcome: Outcome::Pushed,
                text,
            })
        }
        Op::Fetch => failed(adapter.fetch(&access).await, |text| Driven {
            outcome: Outcome::Fetched,
            text,
        }),
    }
}

/// What went wrong for one case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// The fake has no scenario for the case.
    FakeLacksCase(Case),
    /// The subject has no code for the case.
    SubjectLacksCase(Case),
    /// The outcome differs from the table.
    Mismatch {
        /// The case.
        case: Case,
        /// What the table owes.
        expected: Outcome,
        /// What the subject produced.
        actual: Outcome,
    },
    /// The subject made a number of requests the case does not allow.
    Calls {
        /// The case.
        case: Case,
        /// The number of requests the fake saw.
        seen: usize,
    },
    /// The subject sent `Authorization` after a redirect.
    AuthorizationReplayed(Case),
    /// The outcome text holds the token.
    TokenLeaked(Case),
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FakeLacksCase(case) => write!(f, "fake lacks case {}", case.name()),
            Self::SubjectLacksCase(case) => write!(f, "subject lacks case {}", case.name()),
            Self::Mismatch {
                case,
                expected,
                actual,
            } => write!(
                f,
                "case {}: expected {expected:?}, got {actual:?}",
                case.name()
            ),
            Self::Calls { case, seen } => {
                write!(
                    f,
                    "case {}: {seen} requests, owed {:?}",
                    case.name(),
                    case.calls()
                )
            }
            Self::AuthorizationReplayed(case) => {
                write!(
                    f,
                    "case {}: Authorization replayed after a redirect",
                    case.name()
                )
            }
            Self::TokenLeaked(case) => write!(f, "case {}: token in the outcome text", case.name()),
        }
    }
}

/// The result of one [`run_contract`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    /// The cases the subject ran against a fake that had them.
    pub ran: Vec<Case>,
    /// Everything that went wrong.
    pub findings: Vec<Finding>,
}

impl Report {
    /// `Ok` when the report holds no finding and ran every case of the table.
    ///
    /// # Errors
    ///
    /// The report itself, when it holds a finding or ran fewer cases than the table.
    pub fn into_result(self) -> Result<(), Self> {
        if self.findings.is_empty() && self.ran.len() == Case::ALL.len() {
            Ok(())
        } else {
            Err(self)
        }
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} of {} cases ran", self.ran.len(), Case::ALL.len())?;
        for finding in &self.findings {
            write!(f, "\n  {finding}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Report {}

/// Runs every case of the table. `make_fake` returns a fresh fake of the shape for each case, so
/// a test can hand in a deliberately incomplete fake.
pub async fn run_contract<S: Subject>(
    subject: &S,
    shape: Shape,
    make_fake: impl Fn() -> Fake + Send,
) -> Report {
    let mut report = Report::default();
    for &case in Case::ALL {
        let fake = make_fake();
        if fake.arm(case).is_err() {
            report.findings.push(Finding::FakeLacksCase(case));
            continue;
        }
        let Some(driven) = subject.run(case, &fake).await else {
            report.findings.push(Finding::SubjectLacksCase(case));
            continue;
        };
        report.ran.push(case);
        let actual = driven.outcome;
        let expected = case.expected(shape);
        if actual != expected {
            report.findings.push(Finding::Mismatch {
                case,
                expected,
                actual,
            });
        }
        let seen = fake.request_count();
        if !case.calls().allows(seen) {
            report.findings.push(Finding::Calls { case, seen });
        }
        if fake.authorization_replays() > 0 {
            report.findings.push(Finding::AuthorizationReplayed(case));
        }
        if driven.text.contains(Fake::TOKEN) {
            report.findings.push(Finding::TokenLeaked(case));
        }
    }
    report
}
