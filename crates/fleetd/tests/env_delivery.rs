//! The Environment delivery tree and its sweep (ADR-0067): names as path components, modes,
//! owner, which secrets reach which file, the tmpfs check, shred and the startup sweep.

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use fleet_core::Redactor;
use fleet_proto::v1::{EnvironmentDelivery, GetJobEnvironmentReply, JobEnvironmentSecret};
use fleet_proto::v1::{Job, ReportJobReply, ReportJobRequest};
use fleetd::envd::{
    DELIVERY_DIR, DeliveryError, ENV_FILE_NAME, ERR_ENV_DELIVERY, EnvDelivery, MountCheck, Owner,
    ReleasedEnvironment, sweep_trees,
};
use fleetd::runner::{AgentRunner, JobEnd, Reporter, RunConfig};
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Duration;
use tonic::Status;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MARKER: &str = "zq-marker-value-4471-unlikely";
const JOB: &str = "job1";

#[derive(Debug)]
struct FakeMount(AtomicBool);

impl FakeMount {
    fn tmpfs(yes: bool) -> Arc<Self> {
        Arc::new(Self(AtomicBool::new(yes)))
    }
}

impl MountCheck for FakeMount {
    fn is_tmpfs(&self, _dir: std::os::fd::BorrowedFd<'_>) -> std::io::Result<bool> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

struct Entry {
    name: &'static str,
    value: String,
    visible: bool,
    env: bool,
}

fn entry(name: &'static str, value: &str, visible: bool, env: bool) -> Entry {
    Entry {
        name,
        value: value.to_owned(),
        visible,
        env,
    }
}

fn released(entries: Vec<Entry>) -> ReleasedEnvironment {
    ReleasedEnvironment::from_reply(GetJobEnvironmentReply {
        environment: "prod".into(),
        version: 1,
        secrets: entries
            .into_iter()
            .map(|e| JobEnvironmentSecret {
                name: e.name.into(),
                value: e.value,
                agent_visible: e.visible,
                delivery: if e.env {
                    EnvironmentDelivery::Env.into()
                } else {
                    EnvironmentDelivery::File.into()
                },
            })
            .collect(),
        ..GetJobEnvironmentReply::default()
    })
}

struct Rig {
    root: tempfile::TempDir,
    delivery: Arc<EnvDelivery>,
    uid: u32,
}

fn rig_with(mount: Arc<dyn MountCheck>) -> Result<Rig, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let uid = fs::metadata(root.path())?.uid();
    let delivery = Arc::new(EnvDelivery::new(
        root.path(),
        Owner {
            uid: Some(uid),
            gid: None,
        },
        mount,
    )?);
    fs::create_dir(root.path().join(JOB))?;
    Ok(Rig {
        root,
        delivery,
        uid,
    })
}

fn fresh_rig() -> Result<Rig, Box<dyn std::error::Error>> {
    rig_with(FakeMount::tmpfs(true))
}

impl Rig {
    fn run_dir(&self) -> PathBuf {
        self.root.path().join(JOB)
    }

    fn tree(&self) -> PathBuf {
        self.run_dir().join(DELIVERY_DIR)
    }
}

fn names_in(dir: &Path) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(dir)? {
        names.insert(entry?.file_name().to_string_lossy().into_owned());
    }
    Ok(names)
}

#[test]
fn a_valid_name_is_written_and_every_hostile_name_is_refused_before_any_file_exists() -> TestResult
{
    let rig = fresh_rig()?;
    rig.delivery
        .hold(JOB, released(vec![entry("PVE_TOKEN", MARKER, true, false)]));
    rig.delivery.write_tree(JOB)?;
    assert_eq!(fs::read_to_string(rig.tree().join("PVE_TOKEN"))?, MARKER);
    rig.delivery.end(JOB);

    let long = "A".repeat(65);
    let hostile: Vec<(&str, &str)> = vec![
        ("empty", ""),
        ("slash", "a/b"),
        ("leading slash", "/etc/passwd"),
        ("dot", "."),
        ("dot dot", ".."),
        ("dot dot slash", "../x"),
        ("nul", "a\0b"),
        ("leading dash", "-rf"),
        ("leading digit", "1ABC"),
        ("dot inside", "a.b"),
        ("space", "a b"),
        ("newline", "a\nb"),
        ("backslash", "a\\b"),
        ("non ascii", "caf\u{e9}"),
        ("fullwidth", "\u{ff21}BC"),
        ("over long", long.as_str()),
        ("reserved out dir", "out"),
        ("reserved out dir upper", "OUT"),
        ("env file stem", "envd.env"),
    ];
    for (label, name) in hostile {
        let rig = fresh_rig()?;
        let held = ReleasedEnvironment::from_reply(GetJobEnvironmentReply {
            secrets: vec![JobEnvironmentSecret {
                name: name.into(),
                value: MARKER.into(),
                agent_visible: true,
                delivery: EnvironmentDelivery::File.into(),
            }],
            ..GetJobEnvironmentReply::default()
        });
        rig.delivery.hold(JOB, held);
        let refused = rig.delivery.write_tree(JOB);
        assert_eq!(refused, Err(DeliveryError::InvalidName), "{label}");
        assert!(!rig.tree().exists(), "{label}: a tree exists");
        assert!(names_in(&rig.run_dir())?.is_empty(), "{label}");
    }
    Ok(())
}

#[test]
fn two_names_equal_after_case_folding_are_refused_and_nothing_is_written() -> TestResult {
    let rig = fresh_rig()?;
    rig.delivery.hold(
        JOB,
        released(vec![
            entry("Key", MARKER, true, false),
            entry("KEY", MARKER, true, false),
        ]),
    );
    assert_eq!(
        rig.delivery.write_tree(JOB),
        Err(DeliveryError::DuplicateName)
    );
    assert!(!rig.tree().exists());
    Ok(())
}

#[test]
fn the_tree_is_dir_0700_files_0400_owned_by_the_job_uid_with_no_trailing_newline() -> TestResult {
    let rig = fresh_rig()?;
    rig.delivery.hold(
        JOB,
        released(vec![
            entry("PEM", "-----BEGIN-----\nAAAA\n-----END-----", true, false),
            entry("TOKEN", MARKER, true, false),
            entry("MODE", "fast-mode-value", true, true),
        ]),
    );
    rig.delivery.write_tree(JOB)?;
    let dir = fs::metadata(rig.tree())?;
    assert_eq!(dir.permissions().mode() & 0o7777, 0o700);
    assert_eq!(dir.uid(), rig.uid);
    for name in ["PEM", "TOKEN", ENV_FILE_NAME] {
        let meta = fs::metadata(rig.tree().join(name))?;
        assert_eq!(meta.permissions().mode() & 0o7777, 0o400, "{name}");
        assert_eq!(meta.uid(), rig.uid, "{name}");
        assert!(meta.is_file(), "{name}");
    }
    assert_eq!(fs::read(rig.tree().join("TOKEN"))?, MARKER.as_bytes());
    assert_eq!(
        fs::read(rig.tree().join("PEM"))?,
        b"-----BEGIN-----\nAAAA\n-----END-----"
    );
    Ok(())
}

#[test]
fn a_file_secret_is_never_in_envd_env_an_env_secret_is_never_a_file_and_invisible_is_in_neither()
-> TestResult {
    let rig = fresh_rig()?;
    rig.delivery.hold(
        JOB,
        released(vec![
            entry("AS_FILE", "file-value-0123", true, false),
            entry("AS_ENV", "env-value-0123", true, true),
            entry("SETUP_ONLY", MARKER, false, false),
        ]),
    );
    rig.delivery.write_tree(JOB)?;
    let names = names_in(&rig.tree())?;
    assert_eq!(
        names,
        BTreeSet::from(["AS_FILE".to_owned(), ENV_FILE_NAME.to_owned()])
    );
    let env = fs::read_to_string(rig.tree().join(ENV_FILE_NAME))?;
    assert_eq!(env, "AS_ENV=\"env-value-0123\"\n");
    assert!(!env.contains("file-value-0123"));
    let mut everything = env;
    everything.push_str(&fs::read_to_string(rig.tree().join("AS_FILE"))?);
    assert!(!everything.contains(MARKER));
    Ok(())
}

#[test]
fn an_env_value_is_quoted_for_environment_file_and_a_multi_line_one_is_refused() -> TestResult {
    let rig = fresh_rig()?;
    rig.delivery.hold(
        JOB,
        released(vec![
            entry("Q", "a\"b\\c $HOME %h 'x'", true, true),
            entry("A", "plain-value-0123", true, true),
        ]),
    );
    rig.delivery.write_tree(JOB)?;
    assert_eq!(
        fs::read_to_string(rig.tree().join(ENV_FILE_NAME))?,
        "A=\"plain-value-0123\"\nQ=\"a\\\"b\\\\c $HOME %h 'x'\"\n"
    );

    for bad in ["line1\nline2", "line1\rline2"] {
        let rig = fresh_rig()?;
        rig.delivery
            .hold(JOB, released(vec![entry("ML", bad, true, true)]));
        assert_eq!(
            rig.delivery.write_tree(JOB),
            Err(DeliveryError::EnvMultiline)
        );
        assert!(!rig.tree().exists());
    }
    Ok(())
}

#[test]
fn a_job_with_nothing_for_the_agent_gets_no_tree() -> TestResult {
    let rig = fresh_rig()?;
    rig.delivery.hold(
        JOB,
        released(vec![entry("SETUP_ONLY", MARKER, false, false)]),
    );
    rig.delivery.write_tree(JOB)?;
    assert!(!rig.tree().exists());
    let rig = rig_unheld()?;
    rig.delivery.write_tree(JOB)?;
    assert!(!rig.tree().exists());
    Ok(())
}

fn rig_unheld() -> Result<Rig, Box<dyn std::error::Error>> {
    fresh_rig()
}

#[test]
fn a_run_dir_off_tmpfs_is_refused_and_writes_nothing_and_tmpfs_is_accepted() -> TestResult {
    let mount = FakeMount::tmpfs(false);
    let rig = rig_with(mount.clone())?;
    rig.delivery
        .hold(JOB, released(vec![entry("TOKEN", MARKER, true, false)]));
    assert_eq!(rig.delivery.write_tree(JOB), Err(DeliveryError::NotTmpfs));
    assert!(!rig.tree().exists());
    mount.0.store(true, Ordering::SeqCst);
    rig.delivery.write_tree(JOB)?;
    assert!(rig.tree().join("TOKEN").exists());
    Ok(())
}

#[test]
fn a_relative_root_and_a_hostile_job_id_are_refused() -> TestResult {
    let owner = Owner {
        uid: Some(1),
        gid: None,
    };
    for relative in ["run/fleet", "", ".", "../run"] {
        let made = EnvDelivery::new(Path::new(relative), owner, FakeMount::tmpfs(true));
        assert_eq!(made.err(), Some(DeliveryError::BadPath), "{relative:?}");
    }
    let rig = fresh_rig()?;
    rig.delivery
        .hold("../escape", released(vec![entry("T", MARKER, true, false)]));
    for id in ["../escape", "", "a/b", "."] {
        assert_eq!(
            rig.delivery.write_tree(id),
            Err(DeliveryError::BadPath),
            "{id:?}"
        );
    }
    assert!(!rig.root.path().join("..").join("escape").exists());
    Ok(())
}

#[test]
fn a_uid_the_process_cannot_chown_to_is_refused_and_leaves_no_tree() -> TestResult {
    let root = tempfile::tempdir()?;
    let own = fs::metadata(root.path())?.uid();
    if own == 0 {
        return Ok(());
    }
    fs::create_dir(root.path().join(JOB))?;
    let foreign = if own == 1 { 2 } else { 1 };
    let delivery = EnvDelivery::new(
        root.path(),
        Owner {
            uid: Some(foreign),
            gid: None,
        },
        FakeMount::tmpfs(true),
    )?;
    delivery.hold(JOB, released(vec![entry("TOKEN", MARKER, true, false)]));
    assert!(matches!(
        delivery.write_tree(JOB),
        Err(DeliveryError::Io(_))
    ));
    assert!(!root.path().join(JOB).join(DELIVERY_DIR).exists());
    Ok(())
}

#[test]
fn no_error_or_debug_text_carries_a_value_and_the_marker_control_does() -> TestResult {
    let rig = fresh_rig()?;
    rig.delivery
        .hold(JOB, released(vec![entry("TOKEN", MARKER, true, false)]));
    let debug = format!("{:?}", rig.delivery);
    assert!(!debug.contains(MARKER), "{debug}");
    rig.delivery.write_tree(JOB)?;
    assert!(fs::read_to_string(rig.tree().join("TOKEN"))?.contains(MARKER));

    let errors = [
        DeliveryError::BadPath,
        DeliveryError::NotTmpfs,
        DeliveryError::InvalidName,
        DeliveryError::DuplicateName,
        DeliveryError::EnvMultiline,
        DeliveryError::Io(std::io::ErrorKind::PermissionDenied),
    ];
    for error in errors {
        assert_eq!(error.to_string(), ERR_ENV_DELIVERY);
        assert!(!format!("{error:?}").contains(MARKER));
    }
    let hostile = rig_with(FakeMount::tmpfs(true))?;
    hostile.delivery.hold(
        JOB,
        ReleasedEnvironment::from_reply(GetJobEnvironmentReply {
            secrets: vec![JobEnvironmentSecret {
                name: format!("../{MARKER}"),
                value: MARKER.into(),
                agent_visible: true,
                delivery: EnvironmentDelivery::File.into(),
            }],
            ..GetJobEnvironmentReply::default()
        }),
    );
    let refused = hostile.delivery.write_tree(JOB).err().ok_or("accepted")?;
    assert!(!format!("{refused:?}{refused}").contains(MARKER));
    Ok(())
}

#[test]
fn a_symlink_planted_as_the_tree_is_not_followed_and_its_target_is_untouched() -> TestResult {
    let rig = fresh_rig()?;
    let target = rig.root.path().join("target");
    fs::create_dir(&target)?;
    fs::write(target.join("keep"), MARKER)?;
    symlink(&target, rig.tree())?;
    rig.delivery
        .hold(JOB, released(vec![entry("TOKEN", MARKER, true, false)]));
    assert!(rig.delivery.write_tree(JOB).is_err());
    assert_eq!(names_in(&target)?, BTreeSet::from(["keep".to_owned()]));
    assert_eq!(fs::read_to_string(target.join("keep"))?, MARKER);
    Ok(())
}

#[test]
fn a_second_write_for_the_same_job_is_refused_and_keeps_the_first_tree() -> TestResult {
    let rig = fresh_rig()?;
    rig.delivery
        .hold(JOB, released(vec![entry("TOKEN", MARKER, true, false)]));
    rig.delivery.write_tree(JOB)?;
    assert!(rig.delivery.write_tree(JOB).is_err());
    assert_eq!(fs::read_to_string(rig.tree().join("TOKEN"))?, MARKER);
    Ok(())
}

#[test]
fn shred_overwrites_the_bytes_before_it_unlinks_and_removes_the_tree() -> TestResult {
    let rig = fresh_rig()?;
    rig.delivery
        .hold(JOB, released(vec![entry("TOKEN", MARKER, true, false)]));
    rig.delivery.write_tree(JOB)?;
    let alias = rig.root.path().join("alias");
    fs::hard_link(rig.tree().join("TOKEN"), &alias)?;
    assert_eq!(fs::read_to_string(&alias)?, MARKER);
    rig.delivery.end(JOB);
    assert!(!rig.tree().exists());
    assert!(rig.run_dir().exists());
    let after = fs::read(&alias)?;
    assert_eq!(after.len(), MARKER.len());
    assert!(after.iter().all(|byte| *byte == 0), "{after:?}");
    rig.delivery.end(JOB);
    Ok(())
}

#[test]
fn end_unregisters_the_job_only_after_the_tree_is_shredded() -> TestResult {
    let root = tempfile::tempdir()?;
    let uid = fs::metadata(root.path())?.uid();
    fs::create_dir(root.path().join(JOB))?;
    let slot: Arc<Mutex<Option<Arc<EnvDelivery>>>> = Arc::default();
    let seen = Arc::new(Mutex::new(Vec::<(String, bool)>::new()));
    let probe = {
        let slot = Arc::clone(&slot);
        let seen = Arc::clone(&seen);
        Arc::new(move |id: &str| {
            let held = slot
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .is_some_and(|delivery| delivery.is_held(id));
            seen.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((id.to_owned(), held));
        })
    };
    let delivery = Arc::new(
        EnvDelivery::new(
            root.path(),
            Owner {
                uid: Some(uid),
                gid: None,
            },
            FakeMount::tmpfs(true),
        )?
        .with_shred_probe(probe),
    );
    *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&delivery));
    delivery.hold(JOB, released(vec![entry("TOKEN", MARKER, true, false)]));
    delivery.write_tree(JOB)?;
    assert!(delivery.is_held(JOB));
    delivery.end(JOB);
    assert!(!delivery.is_held(JOB));
    assert_eq!(
        *seen.lock().unwrap_or_else(PoisonError::into_inner),
        [(JOB.to_owned(), true)]
    );
    Ok(())
}

#[test]
fn the_job_end_hook_shreds_the_tree_of_the_ended_job_only() -> TestResult {
    let rig = fresh_rig()?;
    fs::create_dir(rig.root.path().join("job2"))?;
    rig.delivery
        .hold(JOB, released(vec![entry("TOKEN", MARKER, true, false)]));
    rig.delivery
        .hold("job2", released(vec![entry("TOKEN", MARKER, true, false)]));
    rig.delivery.write_tree(JOB)?;
    rig.delivery.write_tree("job2")?;
    let end = JobEnd::new().on_end(rig.delivery.end_hook());
    end.fire(JOB);
    assert!(!rig.tree().exists());
    assert!(rig.root.path().join("job2").join(DELIVERY_DIR).exists());
    assert!(!rig.delivery.is_held(JOB));
    assert!(rig.delivery.is_held("job2"));
    Ok(())
}

fn plant(root: &Path, id: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let tree = root.join(id).join(DELIVERY_DIR);
    fs::create_dir_all(&tree)?;
    fs::write(tree.join("TOKEN"), MARKER)?;
    fs::write(tree.join(ENV_FILE_NAME), format!("T=\"{MARKER}\"\n"))?;
    Ok(tree)
}

#[test]
fn the_sweep_removes_the_trees_of_dead_jobs_and_keeps_the_live_one() -> TestResult {
    let root = tempfile::tempdir()?;
    let dead = plant(root.path(), "dead1")?;
    let live = plant(root.path(), "live1")?;
    let aside = plant(root.path(), "dead2")?;
    fs::rename(&aside, root.path().join("dead2").join(".envd-shred"))?;
    sweep_trees(root.path(), &|id| id == "live1");
    assert!(!dead.exists());
    assert!(root.path().join("dead1").exists());
    assert!(!root.path().join("dead2").join(".envd-shred").exists());
    assert_eq!(fs::read_to_string(live.join("TOKEN"))?, MARKER);
    sweep_trees(root.path(), &|_| false);
    assert!(!live.exists());
    Ok(())
}

#[test]
fn the_sweep_removes_a_planted_symlink_as_a_link_and_never_follows_it() -> TestResult {
    let root = tempfile::tempdir()?;
    let target = root.path().join("target");
    fs::create_dir(&target)?;
    fs::write(target.join("keep"), MARKER)?;
    let outside_file = root.path().join("outside-file");
    fs::write(&outside_file, MARKER)?;

    let run = root.path().join("run");
    fs::create_dir_all(run.join("a1"))?;
    symlink(&target, run.join("a1").join(DELIVERY_DIR))?;

    let inner = plant(&run, "b1")?;
    symlink(&target, inner.join("dirlink"))?;
    symlink(&outside_file, inner.join("filelink"))?;

    fs::create_dir_all(run.join("c1"))?;
    symlink(&target, run.join("c1").join(".envd-shred"))?;

    sweep_trees(&run, &|_| false);

    assert!(
        fs::symlink_metadata(run.join("a1").join(DELIVERY_DIR)).is_err(),
        "link kept"
    );
    assert!(!inner.exists());
    assert!(fs::symlink_metadata(run.join("c1").join(".envd-shred")).is_err());
    assert_eq!(names_in(&target)?, BTreeSet::from(["keep".to_owned()]));
    assert_eq!(fs::read_to_string(target.join("keep"))?, MARKER);
    assert_eq!(fs::read_to_string(&outside_file)?, MARKER);
    Ok(())
}

#[test]
fn the_sweep_skips_names_that_are_not_job_ids_and_links_in_place_of_a_run_dir() -> TestResult {
    let root = tempfile::tempdir()?;
    let run = root.path().join("run");
    fs::create_dir(&run)?;
    let hook = plant(&run, "hook")?;
    let odd = plant(&run, "..odd")?;
    let target = root.path().join("elsewhere");
    let kept = plant(&target, "x")?;
    symlink(target.join("x"), run.join("linked"))?;
    sweep_trees(&run, &|_| false);
    assert!(!hook.exists(), "hook is a valid id here");
    assert!(odd.exists(), "an invalid id is left alone");
    assert_eq!(fs::read_to_string(kept.join("TOKEN"))?, MARKER);
    assert!(fs::symlink_metadata(run.join("linked")).is_ok());
    sweep_trees(&root.path().join("missing"), &|_| false);
    Ok(())
}

#[test]
fn a_group_shared_tree_stays_with_the_process_uid_and_is_0750_dir_0440_files() -> TestResult {
    let root = tempfile::tempdir()?;
    let meta = fs::metadata(root.path())?;
    fs::create_dir(root.path().join(JOB))?;
    let delivery = EnvDelivery::new(
        root.path(),
        Owner {
            uid: None,
            gid: Some(meta.gid()),
        },
        FakeMount::tmpfs(true),
    )?;
    delivery.hold(JOB, released(vec![entry("TOKEN", MARKER, true, false)]));
    delivery.write_tree(JOB)?;
    let tree = root.path().join(JOB).join(DELIVERY_DIR);
    let dir = fs::metadata(&tree)?;
    let file = fs::metadata(tree.join("TOKEN"))?;
    assert_eq!(dir.permissions().mode() & 0o7777, 0o750);
    assert_eq!(file.permissions().mode() & 0o7777, 0o440);
    assert_eq!((dir.uid(), dir.gid()), (meta.uid(), meta.gid()));
    assert_eq!(file.uid(), meta.uid());
    delivery.end(JOB);
    assert!(!tree.exists());
    Ok(())
}

struct Silent;

impl Reporter for Silent {
    fn report(
        &self,
        _: ReportJobRequest,
    ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
        std::future::ready(Ok(ReportJobReply::default()))
    }
}

fn job() -> Job {
    Job {
        job_id: JOB.into(),
        attempt: 1,
        ..Job::default()
    }
}

struct Ended {
    rig: Rig,
    runner: Arc<AgentRunner<Silent>>,
    alias: PathBuf,
}

fn ending() -> Result<Ended, Box<dyn std::error::Error>> {
    let rig = fresh_rig()?;
    rig.delivery
        .hold(JOB, released(vec![entry("TOKEN", MARKER, true, false)]));
    rig.delivery.write_tree(JOB)?;
    let alias = rig.root.path().join("alias");
    fs::hard_link(rig.tree().join("TOKEN"), &alias)?;
    let runner = AgentRunner::new(
        RunConfig::new("claude-fake", false),
        Silent,
        Redactor::default(),
    )
    .with_job_end(JobEnd::new().on_end(rig.delivery.end_hook()));
    assert!(rig.tree().join("TOKEN").exists());
    assert!(rig.delivery.is_held(JOB));
    Ok(Ended {
        rig,
        runner: Arc::new(runner),
        alias,
    })
}

fn assert_shredded(ended: &Ended) -> TestResult {
    assert!(!ended.rig.tree().exists());
    assert!(!ended.rig.delivery.is_held(JOB));
    let left = fs::read(&ended.alias)?;
    assert_eq!(left.len(), MARKER.len());
    assert!(left.iter().all(|byte| *byte == 0));
    Ok(())
}

#[tokio::test]
async fn the_tree_is_shredded_when_the_job_succeeds() -> TestResult {
    let ended = ending()?;
    {
        let job = job();
        let _guard = ended.runner.end_guard(&job);
        assert!(ended.rig.tree().exists());
    }
    assert_shredded(&ended)
}

#[tokio::test]
async fn the_tree_is_shredded_when_the_job_fails() -> TestResult {
    let ended = ending()?;
    let failed: Result<(), &str> = {
        let job = job();
        let _guard = ended.runner.end_guard(&job);
        Err("agent failed")
    };
    assert!(failed.is_err());
    assert_shredded(&ended)
}

#[tokio::test]
async fn the_tree_is_shredded_when_the_job_is_cancelled() -> TestResult {
    let ended = ending()?;
    let (started, mut running) = tokio::sync::mpsc::unbounded_channel();
    let task = tokio::spawn({
        let runner = Arc::clone(&ended.runner);
        async move {
            let job = job();
            let _guard = runner.end_guard(&job);
            let _ = started.send(());
            std::future::pending::<()>().await;
        }
    });
    running.recv().await.ok_or("never started")?;
    assert!(ended.rig.tree().exists());
    task.abort();
    let _ = task.await;
    assert_shredded(&ended)
}

#[tokio::test]
async fn the_tree_is_shredded_when_the_lease_is_lost_and_the_job_ends_twice() -> TestResult {
    let ended = ending()?;
    let job = job();
    ended.runner.end_job(&job);
    assert_shredded(&ended)?;
    ended.runner.end_job(&job);
    assert_shredded(&ended)
}

#[tokio::test]
async fn the_tree_is_shredded_when_the_job_times_out() -> TestResult {
    let ended = ending()?;
    let job = job();
    let timed = tokio::time::timeout(Duration::from_millis(50), async {
        let _guard = ended.runner.end_guard(&job);
        std::future::pending::<()>().await;
    })
    .await;
    assert!(timed.is_err());
    assert_shredded(&ended)
}

#[tokio::test]
async fn the_tree_is_shredded_when_the_job_panics() -> TestResult {
    let ended = ending()?;
    let job = job();
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let _guard = ended.runner.end_guard(&job);
        assert!(std::hint::black_box(false), "job panic");
    }));
    assert!(unwound.is_err());
    assert_shredded(&ended)
}

#[tokio::test]
async fn a_job_that_has_not_ended_keeps_its_tree_as_the_positive_control() -> TestResult {
    let ended = ending()?;
    assert!(ended.rig.tree().join("TOKEN").exists());
    assert_eq!(fs::read_to_string(&ended.alias)?, MARKER);
    Ok(())
}
