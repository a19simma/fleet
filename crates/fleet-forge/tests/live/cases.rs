//! The live plan: which contract cases run against the live forge and in which order. Every
//! case of the shared table appears here once, either run or skipped with its reason.

use fleet_forge::contract::Case;

pub(crate) enum Plan {
    Run,
    Skip(&'static str),
}

const NEEDS_FAULT: &str = "needs a fault the live forge cannot be told to inject";

pub(crate) const fn plan(case: Case) -> Plan {
    match case {
        Case::IdentifyOk
        | Case::VerifyReadPush
        | Case::Verify404
        | Case::Verify401
        | Case::VerifyRedirect
        | Case::CreatePrOk
        | Case::CreatePrExists
        | Case::CreatePrRejected
        | Case::CiPending
        | Case::CiSuccess
        | Case::CiFailure
        | Case::CiNone
        | Case::CiMixed
        | Case::Ci404
        | Case::CiChecksNone
        | Case::CiChecks404
        | Case::PushOk
        | Case::PushNonFastForward
        | Case::PushRevoked
        | Case::FetchOk
        | Case::FetchAuthFailure
        | Case::CredentialOtherHost => Plan::Run,
        Case::IdentifyNonForge | Case::IdentifyWrongKind => {
            Plan::Skip("needs a second host that is not Forgejo")
        }
        Case::VerifyReadOnly => Plan::Skip("needs a token without write permission"),
        Case::VerifyNoPermissions => Plan::Skip("the live forge always reports permissions"),
        Case::Verify403 => Plan::Skip("needs a second account; the anonymous probe records it"),
        Case::Verify5xx
        | Case::VerifyReset
        | Case::VerifySlow
        | Case::VerifyOverCap
        | Case::RedactedError
        | Case::CiChecksBadName
        | Case::CiChecksOverCap => Plan::Skip(NEEDS_FAULT),
        Case::CiChecksMixed => {
            Plan::Skip("commit status contexts are unique, so no duplicate name")
        }
    }
}

pub(crate) const ORDER: &[Case] = &[
    Case::IdentifyOk,
    Case::VerifyReadPush,
    Case::Verify404,
    Case::Verify401,
    Case::VerifyRedirect,
    Case::CredentialOtherHost,
    Case::FetchAuthFailure,
    Case::FetchOk,
    Case::PushRevoked,
    Case::PushOk,
    Case::PushNonFastForward,
    Case::CreatePrRejected,
    Case::CreatePrOk,
    Case::CreatePrExists,
    Case::CiNone,
    Case::CiChecksNone,
    Case::Ci404,
    Case::CiChecks404,
    Case::CiPending,
    Case::CiSuccess,
    Case::CiFailure,
    Case::CiMixed,
];
