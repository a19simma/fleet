//! `FleetRetro` RPCs: retros, improvements, pitfalls and the work brief. The tests call the
//! handlers with a [`Caller`] extension, and one goes through `router` to check the production
//! redactor wiring. They need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_core::Redactor;
use fleet_proto::v1::fleet_retro_client::FleetRetroClient;
use fleet_proto::v1::fleet_retro_server::FleetRetro;
use fleet_proto::v1::fleet_work_server::FleetWork;
use fleet_proto::v1::{
    AddWorkItemRequest, CloseRetroRequest, CreateWorkProjectRequest, DispositionImprovementRequest,
    FileImprovementRequest, GetWorkBriefRequest, Improvement, ImprovementDisposition,
    ImprovementKind, ListImprovementsRequest, ListPitfallsRequest, ListRetrosRequest,
    OpenRetroRequest, Pitfall, RecordPitfallRequest, Retro, RetroState, SetWorkSlicesRequest,
    WorkSlice,
};
use fleet_server::auth::{BearerAuth, Caller};
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::service::{FleetService, router};
use fleet_server::store::{MAX_BRIEF_CANDIDATES, MAX_OCCURRENCES, Store};
use sqlx::PgPool;
use tonic::metadata::MetadataValue;
use tonic::transport::Endpoint;
use tonic::transport::server::TcpIncoming;
use tonic::{Code, Request, Status};

struct World {
    svc: FleetService,
    pool: PgPool,
    alice: i64,
    bob: i64,
}

fn as_user<T>(user_id: i64, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(Caller {
        user_id,
        is_admin: false,
    });
    request
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn world(pool: PgPool) -> World {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let svc = FleetService::new(store).with_work_redactor(Redactor::new(["s3cr3t-token-value"]));
    let world = World {
        svc,
        pool,
        alice,
        bob,
    };
    world.project(alice, "p").await;
    world
}

impl World {
    async fn project(&self, user: i64, name: &str) {
        self.svc
            .create_work_project(as_user(
                user,
                CreateWorkProjectRequest {
                    key: format!("create-{name}"),
                    name: name.to_owned(),
                    repo: None,
                },
            ))
            .await
            .unwrap();
    }

    async fn item(&self, key: &str, slices: &[&str]) {
        let names: Vec<WorkSlice> = slices
            .iter()
            .map(|s| WorkSlice {
                name: (*s).to_owned(),
                paths: vec![format!("src/{s}")],
            })
            .collect();
        if !names.is_empty() {
            self.svc
                .set_work_slices(as_user(
                    self.alice,
                    SetWorkSlicesRequest {
                        key: format!("slices-{key}"),
                        project: "p".to_owned(),
                        slices: names,
                        mergeable: Vec::new(),
                    },
                ))
                .await
                .unwrap();
        }
        self.svc
            .add_work_item(as_user(
                self.alice,
                AddWorkItemRequest {
                    key: format!("item-{key}"),
                    project: "p".to_owned(),
                    item_key: key.to_owned(),
                    title: format!("title {key}"),
                    body: "body".to_owned(),
                    slices: slices.iter().map(|s| (*s).to_owned()).collect(),
                    deps: Vec::new(),
                },
            ))
            .await
            .unwrap();
    }

    async fn open(&self, user: i64, key: &str, title: &str) -> Result<Retro, Status> {
        self.svc
            .open_retro(as_user(
                user,
                OpenRetroRequest {
                    key: key.to_owned(),
                    project: "p".to_owned(),
                    title: title.to_owned(),
                    span_from_item_key: None,
                    span_to_item_key: None,
                },
            ))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn close(&self, user: i64, key: &str, retro: u64) -> Result<Retro, Status> {
        self.svc
            .close_retro(as_user(
                user,
                CloseRetroRequest {
                    key: key.to_owned(),
                    project: "p".to_owned(),
                    retro_id: retro,
                },
            ))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn file(
        &self,
        user: i64,
        key: &str,
        retro: Option<u64>,
        title: &str,
    ) -> Result<Improvement, Status> {
        self.svc
            .file_improvement(as_user(user, filing(key, retro, title)))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn decide(
        &self,
        key: &str,
        improvement: u64,
        disposition: ImprovementDisposition,
    ) -> Result<Improvement, Status> {
        self.svc
            .disposition_improvement(as_user(
                self.alice,
                DispositionImprovementRequest {
                    key: key.to_owned(),
                    project: "p".to_owned(),
                    improvement_id: improvement,
                    disposition: disposition as i32,
                    reason: "because".to_owned(),
                },
            ))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn pitfall(
        &self,
        user: i64,
        key: &str,
        project: Option<&str>,
        symptom: &str,
    ) -> Result<Pitfall, Status> {
        self.svc
            .record_pitfall(as_user(
                user,
                RecordPitfallRequest {
                    key: key.to_owned(),
                    project: project.map(str::to_owned),
                    symptom: symptom.to_owned(),
                    cause: "cause".to_owned(),
                    fix: "fix".to_owned(),
                },
            ))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn brief(&self, user: i64, item: &str) -> Result<(String, u32), Status> {
        self.svc
            .get_work_brief(as_user(
                user,
                GetWorkBriefRequest {
                    project: "p".to_owned(),
                    item_key: item.to_owned(),
                },
            ))
            .await
            .map(|reply| {
                let reply = reply.into_inner();
                (reply.text, reply.dropped)
            })
    }

    async fn improvements(&self) -> Vec<Improvement> {
        self.svc
            .list_improvements(as_user(
                self.alice,
                ListImprovementsRequest {
                    project: "p".to_owned(),
                    vertical: None,
                    retro_id: None,
                    undecided: None,
                },
            ))
            .await
            .unwrap()
            .into_inner()
            .improvements
    }

    async fn occurrence_rows(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM improvement_occurrence")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

fn filing(key: &str, retro: Option<u64>, title: &str) -> FileImprovementRequest {
    FileImprovementRequest {
        key: key.to_owned(),
        project: "p".to_owned(),
        retro_id: retro,
        item_key: None,
        attempt_id: None,
        vertical: "server".to_owned(),
        title: title.to_owned(),
        body: "body".to_owned(),
        kind: ImprovementKind::Process as i32,
    }
}

#[sqlx::test]
async fn close_is_refused_while_an_improvement_lacks_a_disposition(pool: PgPool) {
    let w = world(pool).await;
    let retro = w.open(w.alice, "o", "review").await.unwrap();
    assert_eq!(retro.state, RetroState::Open as i32);
    let first = w.file(w.alice, "f1", Some(retro.id), "one").await.unwrap();
    let second = w.file(w.alice, "f2", Some(retro.id), "two").await.unwrap();
    let refused = w.close(w.alice, "c1", retro.id).await.unwrap_err();
    assert_eq!(refused.code(), Code::FailedPrecondition);
    assert_eq!(
        refused.message(),
        "retro has 2 improvements without a disposition"
    );
    w.decide("d1", first.id, ImprovementDisposition::Accepted)
        .await
        .unwrap();
    let refused = w.close(w.alice, "c2", retro.id).await.unwrap_err();
    assert_eq!(
        refused.message(),
        "retro has 1 improvements without a disposition"
    );
    w.decide("d2", second.id, ImprovementDisposition::Deferred)
        .await
        .unwrap();
    let closed = w.close(w.alice, "c3", retro.id).await.unwrap();
    assert_eq!(closed.state, RetroState::Closed as i32);
    assert!(closed.closed_at_ms.is_some());
    let again = w.close(w.alice, "c4", retro.id).await.unwrap_err();
    assert_eq!(again.code(), Code::FailedPrecondition);
    let into_closed = w.file(w.alice, "f3", Some(retro.id), "three").await;
    assert_eq!(into_closed.unwrap_err().code(), Code::FailedPrecondition);
}

#[sqlx::test]
async fn filing_a_title_again_counts_one_occurrence_and_one_row(pool: PgPool) {
    let w = world(pool).await;
    let first = w.file(w.alice, "f1", None, "same").await.unwrap();
    assert_eq!(first.occurrences, 1);
    assert_eq!(w.occurrence_rows().await, 1);
    let second = w.file(w.alice, "f2", None, "same").await.unwrap();
    assert_eq!(second.id, first.id);
    assert_eq!(second.occurrences, 2);
    assert_eq!(w.occurrence_rows().await, 2);
    let replay = w.file(w.alice, "f2", None, "same").await.unwrap();
    assert_eq!(replay.occurrences, 2);
    assert_eq!(w.occurrence_rows().await, 2);
    let other = w.file(w.alice, "f3", None, "other").await.unwrap();
    assert_eq!(other.occurrences, 1);
    assert_eq!(w.occurrence_rows().await, 3);
}

#[sqlx::test]
async fn concurrent_filings_of_one_title_count_every_occurrence(pool: PgPool) {
    let w = world(pool).await;
    let mut tasks = Vec::new();
    for n in 0..12 {
        let svc = w.svc.clone();
        let alice = w.alice;
        tasks.push(tokio::spawn(async move {
            svc.file_improvement(as_user(alice, filing(&format!("k{n}"), None, "race")))
                .await
        }));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    let listed = w.improvements().await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].occurrences, 12);
    assert_eq!(w.occurrence_rows().await, 12);
}

#[sqlx::test]
async fn an_attempt_of_another_project_rolls_the_count_back(pool: PgPool) {
    let w = world(pool).await;
    let first = w.file(w.alice, "f1", None, "same").await.unwrap();
    let mut request = filing("f2", None, "same");
    request.attempt_id = Some(9_999_999);
    let refused = w
        .svc
        .file_improvement(as_user(w.alice, request))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::NotFound);
    let after = w.improvements().await;
    assert_eq!(after[0].id, first.id);
    assert_eq!(after[0].occurrences, 1);
    assert_eq!(w.occurrence_rows().await, 1);
}

#[sqlx::test]
async fn occurrences_stop_at_the_limit(pool: PgPool) {
    let w = world(pool).await;
    let first = w.file(w.alice, "f1", None, "same").await.unwrap();
    sqlx::query("UPDATE improvement SET occurrences = $1 WHERE id = $2")
        .bind(MAX_OCCURRENCES - 1)
        .bind(i64::try_from(first.id).unwrap())
        .execute(&w.pool)
        .await
        .unwrap();
    let at = w.file(w.alice, "f2", None, "same").await.unwrap();
    assert_eq!(i64::from(at.occurrences), i64::from(MAX_OCCURRENCES));
    let over = w.file(w.alice, "f3", None, "same").await.unwrap_err();
    assert_eq!(over.code(), Code::FailedPrecondition);
    assert_eq!(w.occurrence_rows().await, 2);
}

fn answer<T>(result: Result<T, Status>) -> (Code, String) {
    result.map_or_else(
        |err| (err.code(), err.message().to_owned()),
        |_| (Code::Ok, String::new()),
    )
}

#[expect(clippy::too_many_lines, reason = "one request per rpc")]
async fn nine(
    w: &World,
    user: i64,
    project: &str,
    retro: u64,
    improvement: u64,
) -> Vec<(Code, String)> {
    let p = project.to_owned();
    vec![
        answer(
            w.svc
                .open_retro(as_user(
                    user,
                    OpenRetroRequest {
                        key: "n1".into(),
                        project: p.clone(),
                        title: "t".into(),
                        span_from_item_key: None,
                        span_to_item_key: None,
                    },
                ))
                .await,
        ),
        answer(
            w.svc
                .close_retro(as_user(
                    user,
                    CloseRetroRequest {
                        key: "n2".into(),
                        project: p.clone(),
                        retro_id: retro,
                    },
                ))
                .await,
        ),
        answer(
            w.svc
                .list_retros(as_user(
                    user,
                    ListRetrosRequest {
                        project: p.clone(),
                        state: None,
                    },
                ))
                .await,
        ),
        answer({
            let mut request = filing("n4", Some(retro), "t");
            request.project.clone_from(&p);
            w.svc.file_improvement(as_user(user, request)).await
        }),
        answer(
            w.svc
                .list_improvements(as_user(
                    user,
                    ListImprovementsRequest {
                        project: p.clone(),
                        vertical: None,
                        retro_id: Some(retro),
                        undecided: None,
                    },
                ))
                .await,
        ),
        answer(
            w.svc
                .disposition_improvement(as_user(
                    user,
                    DispositionImprovementRequest {
                        key: "n6".into(),
                        project: p.clone(),
                        improvement_id: improvement,
                        disposition: ImprovementDisposition::Accepted as i32,
                        reason: "r".into(),
                    },
                ))
                .await,
        ),
        answer(
            w.svc
                .record_pitfall(as_user(
                    user,
                    RecordPitfallRequest {
                        key: "n7".into(),
                        project: Some(p.clone()),
                        symptom: "s".into(),
                        cause: "c".into(),
                        fix: "f".into(),
                    },
                ))
                .await,
        ),
        answer(
            w.svc
                .list_pitfalls(as_user(
                    user,
                    ListPitfallsRequest {
                        project: Some(p.clone()),
                    },
                ))
                .await,
        ),
        answer(
            w.svc
                .get_work_brief(as_user(
                    user,
                    GetWorkBriefRequest {
                        project: p,
                        item_key: "w1".into(),
                    },
                ))
                .await,
        ),
    ]
}

#[sqlx::test]
async fn every_rpc_answers_foreign_and_unknown_alike(pool: PgPool) {
    let w = world(pool).await;
    let retro = w.open(w.alice, "o", "review").await.unwrap();
    let improvement = w.file(w.alice, "f1", Some(retro.id), "one").await.unwrap();
    w.item("w1", &["a"]).await;
    w.project(w.bob, "q").await;
    let foreign_project = nine(&w, w.bob, "p", retro.id, improvement.id).await;
    let unknown_project = nine(&w, w.bob, "nope", retro.id, improvement.id).await;
    assert_eq!(foreign_project, unknown_project);
    for (code, message) in &foreign_project {
        assert_eq!(*code, Code::NotFound);
        assert_eq!(message, "work project not found");
    }
    let foreign_ids = nine(&w, w.bob, "q", retro.id, improvement.id).await;
    let unknown_ids = nine(&w, w.bob, "q", 888_888, 777_777).await;
    assert_eq!(foreign_ids, unknown_ids);
    assert_eq!(w.occurrence_rows().await, 1);
    assert_eq!(w.improvements().await.len(), 1);
}

#[sqlx::test]
async fn client_numbers_past_the_row_range_are_refused(pool: PgPool) {
    let w = world(pool).await;
    let closed = w.close(w.alice, "c", u64::MAX).await.unwrap_err();
    assert_eq!(closed.code(), Code::InvalidArgument);
    let decided = w
        .decide("d", u64::MAX, ImprovementDisposition::Accepted)
        .await
        .unwrap_err();
    assert_eq!(decided.code(), Code::InvalidArgument);
    let filed = w.file(w.alice, "f", Some(u64::MAX), "t").await.unwrap_err();
    assert_eq!(filed.code(), Code::InvalidArgument);
    let mut request = filing("g", None, "t");
    request.attempt_id = Some(u64::MAX);
    let filed = w.svc.file_improvement(as_user(w.alice, request)).await;
    assert_eq!(filed.unwrap_err().code(), Code::InvalidArgument);
}

#[sqlx::test]
async fn a_key_replays_the_first_reply_and_refuses_other_text(pool: PgPool) {
    let w = world(pool).await;
    let first = w.open(w.alice, "same", "review").await.unwrap();
    let replay = w.open(w.alice, "same", "review").await.unwrap();
    assert_eq!(first, replay);
    let other = w.open(w.alice, "same", "different").await.unwrap_err();
    assert_eq!(other.code(), Code::AlreadyExists);
    let listed = w
        .svc
        .list_retros(as_user(
            w.alice,
            ListRetrosRequest {
                project: "p".into(),
                state: None,
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.retros.len(), 1);
}

#[sqlx::test]
async fn decided_improvements_move_only_from_deferred_or_accepted(pool: PgPool) {
    let w = world(pool).await;
    let made = w.file(w.alice, "f1", None, "one").await.unwrap();
    let bad = w
        .decide("d0", made.id, ImprovementDisposition::Unspecified)
        .await
        .unwrap_err();
    assert_eq!(bad.code(), Code::InvalidArgument);
    w.decide("d1", made.id, ImprovementDisposition::Deferred)
        .await
        .unwrap();
    let applied = w
        .decide("d2", made.id, ImprovementDisposition::Applied)
        .await
        .unwrap();
    assert_eq!(
        applied.disposition,
        Some(ImprovementDisposition::Applied as i32)
    );
    assert_eq!(applied.disposition_reason.as_deref(), Some("because"));
    let final_ = w
        .decide("d3", made.id, ImprovementDisposition::Rejected)
        .await
        .unwrap_err();
    assert_eq!(final_.code(), Code::FailedPrecondition);
}

#[sqlx::test]
async fn user_level_pitfalls_belong_to_their_owner(pool: PgPool) {
    let w = world(pool).await;
    let mine = w.pitfall(w.alice, "p1", None, "slow build").await.unwrap();
    assert_eq!(mine.project, None);
    assert_eq!(mine.hits, 0);
    w.pitfall(w.alice, "p2", Some("p"), "slow build")
        .await
        .unwrap();
    let list = |user: i64, project: Option<&str>| {
        let request = ListPitfallsRequest {
            project: project.map(str::to_owned),
        };
        w.svc.list_pitfalls(as_user(user, request))
    };
    let user_level = list(w.alice, None).await.unwrap().into_inner().pitfalls;
    assert_eq!(user_level.len(), 1);
    assert_eq!(user_level[0].id, mine.id);
    let project_level = list(w.alice, Some("p"))
        .await
        .unwrap()
        .into_inner()
        .pitfalls;
    assert_eq!(project_level.len(), 1);
    assert_eq!(project_level[0].project.as_deref(), Some("p"));
    let bobs = list(w.bob, None).await.unwrap().into_inner().pitfalls;
    assert_eq!(bobs, Vec::new());
    let theirs = w.pitfall(w.bob, "b1", None, "slow build").await.unwrap();
    assert_ne!(theirs.id, mine.id);
    assert_eq!(theirs.hits, 0);
    let again = w.pitfall(w.alice, "p3", None, "slow build").await.unwrap();
    assert_eq!(again.id, mine.id);
    assert_eq!(again.hits, 1);
    assert!(again.last_hit_at_ms.is_some());
    let mut other_text = RecordPitfallRequest {
        key: "p4".into(),
        project: None,
        symptom: "slow build".into(),
        cause: "different".into(),
        fix: "fix".into(),
    };
    let clash = w
        .svc
        .record_pitfall(as_user(w.alice, other_text.clone()))
        .await
        .unwrap_err();
    assert_eq!(clash.code(), Code::AlreadyExists);
    other_text.project = Some("nope".into());
    let foreign = w
        .svc
        .record_pitfall(as_user(w.bob, other_text))
        .await
        .unwrap_err();
    assert_eq!(foreign.code(), Code::NotFound);
}

#[sqlx::test]
async fn the_brief_ranks_pitfalls_and_improvements(pool: PgPool) {
    let w = world(pool).await;
    w.item("w1", &["server"]).await;
    w.pitfall(w.alice, "a", None, "rare trap").await.unwrap();
    w.pitfall(w.alice, "b", None, "common trap").await.unwrap();
    w.pitfall(w.alice, "c", None, "common trap").await.unwrap();
    w.pitfall(w.alice, "d", None, "common trap").await.unwrap();
    w.pitfall(w.bob, "e", None, "bobs trap").await.unwrap();
    w.file(w.alice, "f1", None, "seen once").await.unwrap();
    w.file(w.alice, "f2", None, "seen twice").await.unwrap();
    w.file(w.alice, "f3", None, "seen twice").await.unwrap();
    let rejected = w.file(w.alice, "f4", None, "rejected one").await.unwrap();
    w.decide("d", rejected.id, ImprovementDisposition::Rejected)
        .await
        .unwrap();
    let mut elsewhere = filing("f5", None, "other vertical");
    elsewhere.vertical = "web".into();
    w.svc
        .file_improvement(as_user(w.alice, elsewhere))
        .await
        .unwrap();
    let (text, dropped) = w.brief(w.alice, "w1").await.unwrap();
    assert_eq!(dropped, 0);
    let at = |needle: &str| {
        text.find(needle)
            .unwrap_or_else(|| panic!("missing {needle}"))
    };
    assert!(text.starts_with("work item w1: title w1\nslices: server\n"));
    assert!(at("common trap") < at("rare trap"));
    assert!(at("rare trap") < at("seen twice"));
    assert!(at("seen twice") < at("seen once"));
    for absent in ["bobs trap", "rejected one", "other vertical"] {
        assert!(!text.contains(absent), "{absent}");
    }
    let missing = w.brief(w.alice, "none").await.unwrap_err();
    assert_eq!(missing.code(), Code::NotFound);
    let foreign = w.brief(w.bob, "w1").await.unwrap_err();
    assert_eq!(foreign.code(), Code::NotFound);
}

#[sqlx::test]
async fn the_brief_drops_the_lowest_ranked_entries_and_counts_them(pool: PgPool) {
    let w = world(pool).await;
    w.item("w1", &[]).await;
    let total = MAX_BRIEF_CANDIDATES + 50;
    sqlx::query(
        "INSERT INTO pitfall (user_id, symptom, cause, fix, hits) \
         SELECT $1, 'symptom number ' || n, 'cause', 'fix', n::int FROM generate_series(1, $2) n",
    )
    .bind(w.alice)
    .bind(total)
    .execute(&w.pool)
    .await
    .unwrap();
    let (text, dropped) = w.brief(w.alice, "w1").await.unwrap();
    let budget = fleet_server::store::BRIEF_TOKEN_BUDGET * fleet_server::store::BYTES_PER_TOKEN;
    assert!(text.len() <= budget, "{} > {budget}", text.len());
    let shown = text.matches("pitfall: ").count();
    assert!(shown > 0);
    assert_eq!(i64::try_from(shown).unwrap() + i64::from(dropped), total);
    assert!(text.contains(&format!("symptom number {total} ")));
    assert!(!text.contains("symptom number 1 "));
    assert!(text.contains(&format!("[{dropped} lower-ranked entries dropped]")));
}

#[sqlx::test]
async fn improvements_past_the_candidate_cap_count_once_as_unseen(pool: PgPool) {
    let w = world(pool).await;
    w.item("w1", &["server"]).await;
    let total = MAX_BRIEF_CANDIDATES + 50;
    sqlx::query(
        "INSERT INTO improvement (project_id, vertical, title, body, kind, occurrences) \
         SELECT p.id, 'server', 'improvement number ' || n, 'detail', 'other', n::int \
         FROM work_project p, generate_series(1, $1) n WHERE p.name = 'p'",
    )
    .bind(total)
    .execute(&w.pool)
    .await
    .unwrap();
    let (text, dropped) = w.brief(w.alice, "w1").await.unwrap();
    let budget = fleet_server::store::BRIEF_TOKEN_BUDGET * fleet_server::store::BYTES_PER_TOKEN;
    assert!(text.len() <= budget, "{} > {budget}", text.len());
    let shown = text.matches("improvement (x").count();
    assert!(shown > 0);
    assert_eq!(i64::try_from(shown).unwrap() + i64::from(dropped), total);
    assert!(text.contains(&format!("[{dropped} lower-ranked entries dropped]")));
}

#[sqlx::test]
async fn free_text_is_redacted_before_it_is_cut_and_nul_is_stripped(pool: PgPool) {
    let w = world(pool).await;
    let secret = "s3cr3t-token-value";
    let title = format!("{}{secret}", "a".repeat(195));
    let made = w.file(w.alice, "f1", None, &title).await.unwrap();
    assert!(made.title.chars().count() <= 200);
    for cut in 1..=secret.len() {
        assert!(!made.title.contains(&secret[..cut]), "prefix {cut} leaked");
    }
    let mut request = filing("f2", None, "nul");
    request.body = format!("x\0y {secret}");
    let made = w
        .svc
        .file_improvement(as_user(w.alice, request))
        .await
        .unwrap()
        .into_inner();
    assert!(made.body.starts_with("xy "));
    assert!(!made.body.contains(secret));
    assert!(!made.body.contains('\0'));
    let stored = w
        .svc
        .record_pitfall(as_user(
            w.alice,
            RecordPitfallRequest {
                key: "p".into(),
                project: None,
                symptom: format!("saw {secret}"),
                cause: "c".into(),
                fix: "f".into(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(!stored.symptom.contains(secret));
    let blank = w.file(w.alice, "f3", None, "\0\0").await.unwrap_err();
    assert_eq!(blank.code(), Code::InvalidArgument);
}

fn authed<T>(api: &str, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("Bearer {api}")).unwrap(),
    );
    request
}

#[sqlx::test]
async fn the_served_router_masks_the_client_token_in_a_retro_title(pool: PgPool) {
    const CLIENT: &str = "client-token-0123456789abcdef012345";
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let alice = user(&pool, "alice").await;
    let users = Users::new(pool.clone());
    let made = users.create_api_token(alice, "t").await.unwrap();
    let api = String::from_utf8(made.token.expose().to_vec()).unwrap();
    let auth = BearerAuth::new(
        &Token::new("box-token-0123456789abcdef0123456789".to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    )
    .with_users(users);
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = incoming.local_addr().unwrap();
    tokio::spawn(router(&store, &auth).serve_with_incoming(incoming));
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy();
    let mut work = fleet_proto::v1::fleet_work_client::FleetWorkClient::new(channel.clone());
    let mut retro = FleetRetroClient::new(channel);
    work.create_work_project(authed(
        &api,
        CreateWorkProjectRequest {
            key: "k".into(),
            name: "p".into(),
            repo: None,
        },
    ))
    .await
    .unwrap();
    let opened = retro
        .open_retro(authed(
            &api,
            OpenRetroRequest {
                key: "o".into(),
                project: "p".into(),
                title: format!("leak {CLIENT}"),
                span_from_item_key: None,
                span_to_item_key: None,
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(!opened.title.contains(CLIENT));
}

#[test]
fn the_brief_budget_constants_stay_in_step() {
    assert_eq!(fleet_server::store::BYTES_PER_TOKEN, 4);
    assert_eq!(fleet_server::store::BRIEF_TOKEN_BUDGET, 2000);
}
