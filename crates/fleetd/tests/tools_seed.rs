//! Warm build caches: the per-job copy of the read-only seed, its caps and hostile seed
//! contents, and the job env names, with a tempdir root and a relative root.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use fleetd::tools::{
    CARGO_HOME_DIR, CARGO_SUBDIR, MAX_SEED_BYTES, MAX_SEED_DEPTH, MAX_SEED_ENTRIES,
    MAX_SEED_FILE_BYTES, NPM_CACHE_DIR, NPM_SUBDIR, SeedLimits, ToolsError, cache_env,
    warm_job_caches,
};
use tempfile::TempDir;

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                out.insert(path.clone(), format!("{:o}", meta.mode()).into_bytes());
                stack.push(path);
            } else if meta.is_file() {
                out.insert(path.clone(), fs::read(&path).unwrap());
            } else {
                out.insert(path, b"other".to_vec());
            }
        }
    }
    out
}

struct Rig {
    _tmp: TempDir,
    seed: PathBuf,
    job: PathBuf,
}

fn rig_in(tmp: TempDir, relative: bool) -> Rig {
    let base = if relative {
        PathBuf::from(tmp.path().file_name().unwrap())
    } else {
        tmp.path().to_path_buf()
    };
    let seed = base.join("seed");
    let job = base.join("job");
    fs::create_dir_all(seed.join(CARGO_SUBDIR).join("registry")).unwrap();
    fs::create_dir_all(seed.join(NPM_SUBDIR).join("_cacache")).unwrap();
    fs::create_dir_all(&job).unwrap();
    fs::write(
        seed.join(CARGO_SUBDIR).join("registry").join("crate.bin"),
        b"cargo-bytes",
    )
    .unwrap();
    fs::write(
        seed.join(NPM_SUBDIR).join("_cacache").join("idx"),
        b"npm-bytes",
    )
    .unwrap();
    Rig {
        _tmp: tmp,
        seed,
        job,
    }
}

fn rig() -> Rig {
    rig_in(TempDir::new().unwrap(), false)
}

fn refused(rig: &Rig, limits: SeedLimits) -> ToolsError {
    warm_job_caches(&rig.seed, &rig.job, limits).unwrap_err()
}

fn assert_clean(rig: &Rig) {
    assert_eq!(fs::read_dir(&rig.job).unwrap().count(), 0);
}

#[test]
fn copies_both_caches_into_the_job_dir() {
    let rig = rig();
    let warm = warm_job_caches(&rig.seed, &rig.job, SeedLimits::default()).unwrap();
    assert!(warm.cargo_home().starts_with(&rig.job));
    assert!(warm.npm_cache().starts_with(&rig.job));
    assert_eq!(
        fs::read(warm.cargo_home().join("registry").join("crate.bin")).unwrap(),
        b"cargo-bytes"
    );
    assert_eq!(
        fs::read(warm.npm_cache().join("_cacache").join("idx")).unwrap(),
        b"npm-bytes"
    );
}

#[test]
fn write_in_copy_leaves_seed_byte_identical() {
    let rig = rig();
    let before = snapshot(&rig.seed);
    let warm = warm_job_caches(&rig.seed, &rig.job, SeedLimits::default()).unwrap();
    let copied = warm.cargo_home().join("registry").join("crate.bin");
    let seeded = rig
        .seed
        .join(CARGO_SUBDIR)
        .join("registry")
        .join("crate.bin");
    assert_eq!(fs::metadata(&copied).unwrap().nlink(), 1);
    assert_ne!(
        fs::metadata(&copied).unwrap().ino(),
        fs::metadata(&seeded).unwrap().ino()
    );
    fs::write(&copied, b"mutated").unwrap();
    fs::write(warm.npm_cache().join("new"), b"new").unwrap();
    fs::remove_dir_all(warm.npm_cache().join("_cacache")).unwrap();
    assert_eq!(snapshot(&rig.seed), before);
}

#[test]
fn copy_is_owner_only() {
    let rig = rig();
    let warm = warm_job_caches(&rig.seed, &rig.job, SeedLimits::default()).unwrap();
    let dir_mode = fs::metadata(warm.cargo_home()).unwrap().mode() & 0o777;
    let file_mode = fs::metadata(warm.cargo_home().join("registry").join("crate.bin"))
        .unwrap()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700);
    assert_eq!(file_mode, 0o600);
}

#[test]
fn executable_bit_survives_as_owner_exec() {
    let rig = rig();
    let bin = rig.seed.join(CARGO_SUBDIR).join("tool");
    fs::write(&bin, b"#!/bin/sh\n").unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    let warm = warm_job_caches(&rig.seed, &rig.job, SeedLimits::default()).unwrap();
    let mode = fs::metadata(warm.cargo_home().join("tool")).unwrap().mode() & 0o777;
    assert_eq!(mode, 0o700);
}

#[test]
fn missing_seed_subdirs_give_empty_caches() {
    let tmp = TempDir::new().unwrap();
    let seed = tmp.path().join("seed");
    let job = tmp.path().join("job");
    fs::create_dir_all(&seed).unwrap();
    fs::create_dir_all(&job).unwrap();
    let warm = warm_job_caches(&seed, &job, SeedLimits::default()).unwrap();
    assert_eq!(fs::read_dir(warm.cargo_home()).unwrap().count(), 0);
    assert_eq!(fs::read_dir(warm.npm_cache()).unwrap().count(), 0);
}

#[test]
fn missing_seed_root_gives_empty_caches() {
    let tmp = TempDir::new().unwrap();
    let job = tmp.path().join("job");
    fs::create_dir_all(&job).unwrap();
    let warm = warm_job_caches(&tmp.path().join("absent"), &job, SeedLimits::default()).unwrap();
    assert_eq!(fs::read_dir(warm.cargo_home()).unwrap().count(), 0);
}

#[test]
fn relative_roots_work_and_env_is_absolute() {
    let rig = rig_in(tempfile::tempdir_in(".").unwrap(), true);
    assert!(rig.seed.is_relative());
    assert!(rig.job.is_relative());
    let warm = warm_job_caches(&rig.seed, &rig.job, SeedLimits::default()).unwrap();
    assert!(warm.cargo_home().is_absolute());
    assert!(warm.npm_cache().is_absolute());
    let env = warm.env().unwrap();
    assert!(env.iter().all(|(_, v)| Path::new(v).is_absolute()));
}

#[test]
fn symlink_out_of_tree_is_refused() {
    let rig = rig();
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("secret"), b"s").unwrap();
    symlink(
        outside.path().join("secret"),
        rig.seed.join(CARGO_SUBDIR).join("link"),
    )
    .unwrap();
    assert!(matches!(
        refused(&rig, SeedLimits::default()),
        ToolsError::Seed(_)
    ));
    assert_clean(&rig);
}

#[test]
fn relative_symlink_is_refused() {
    let rig = rig();
    symlink("../npm", rig.seed.join(CARGO_SUBDIR).join("link")).unwrap();
    assert!(matches!(
        refused(&rig, SeedLimits::default()),
        ToolsError::Seed(_)
    ));
}

#[test]
fn symlinked_subdir_root_is_refused() {
    let rig = rig();
    let outside = TempDir::new().unwrap();
    fs::remove_dir_all(rig.seed.join(NPM_SUBDIR)).unwrap();
    symlink(outside.path(), rig.seed.join(NPM_SUBDIR)).unwrap();
    assert!(matches!(
        refused(&rig, SeedLimits::default()),
        ToolsError::Seed(_)
    ));
    assert_clean(&rig);
}

#[test]
fn symlinked_seed_root_is_refused() {
    let rig = rig();
    let link = rig.job.join("seed-link");
    symlink(&rig.seed, &link).unwrap();
    let err = warm_job_caches(&link, &rig.job.join("out"), SeedLimits::default()).unwrap_err();
    assert!(matches!(err, ToolsError::Seed(_)));
}

#[test]
fn hardlinked_file_is_refused() {
    let rig = rig();
    let base = rig.seed.join(CARGO_SUBDIR).join("registry");
    fs::hard_link(base.join("crate.bin"), base.join("twin.bin")).unwrap();
    assert!(matches!(
        refused(&rig, SeedLimits::default()),
        ToolsError::Seed(_)
    ));
    assert_clean(&rig);
}

#[test]
fn fifo_is_refused() {
    let rig = rig();
    let fifo = rig.seed.join(NPM_SUBDIR).join("pipe");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(matches!(
        refused(&rig, SeedLimits::default()),
        ToolsError::Seed(_)
    ));
    assert_clean(&rig);
}

#[test]
fn socket_is_refused() {
    let rig = rig();
    let _listener = UnixListener::bind(rig.seed.join(CARGO_SUBDIR).join("s")).unwrap();
    assert!(matches!(
        refused(&rig, SeedLimits::default()),
        ToolsError::Seed(_)
    ));
}

#[test]
fn existing_destination_is_refused() {
    let rig = rig();
    warm_job_caches(&rig.seed, &rig.job, SeedLimits::default()).unwrap();
    assert!(matches!(
        refused(&rig, SeedLimits::default()),
        ToolsError::Io(_)
    ));
}

#[test]
fn file_size_cap_boundary() {
    let rig = rig();
    fs::write(rig.seed.join(CARGO_SUBDIR).join("big"), vec![7u8; 64]).unwrap();
    let ok = SeedLimits {
        max_file_bytes: 64,
        ..SeedLimits::default()
    };
    warm_job_caches(&rig.seed, &rig.job, ok).unwrap();
    let rig2 = rig_with_big(65);
    let over = SeedLimits {
        max_file_bytes: 64,
        ..SeedLimits::default()
    };
    assert!(matches!(refused(&rig2, over), ToolsError::Seed(_)));
    assert_clean(&rig2);
}

fn rig_with_big(len: usize) -> Rig {
    let rig = rig();
    fs::write(rig.seed.join(CARGO_SUBDIR).join("big"), vec![7u8; len]).unwrap();
    rig
}

#[test]
fn total_bytes_cap_boundary() {
    let exact = "cargo-bytes".len() as u64 + "npm-bytes".len() as u64;
    let rig = rig();
    let ok = SeedLimits {
        max_bytes: exact,
        ..SeedLimits::default()
    };
    warm_job_caches(&rig.seed, &rig.job, ok).unwrap();
    let rig2 = self::rig();
    let over = SeedLimits {
        max_bytes: exact - 1,
        ..SeedLimits::default()
    };
    assert!(matches!(refused(&rig2, over), ToolsError::Seed(_)));
    assert_clean(&rig2);
}

#[test]
fn entry_count_cap_boundary() {
    let rig = rig();
    let entries = 2 + 2 + 2;
    let ok = SeedLimits {
        max_entries: entries,
        ..SeedLimits::default()
    };
    warm_job_caches(&rig.seed, &rig.job, ok).unwrap();
    let rig2 = self::rig();
    let over = SeedLimits {
        max_entries: entries - 1,
        ..SeedLimits::default()
    };
    assert!(matches!(refused(&rig2, over), ToolsError::Seed(_)));
    assert_clean(&rig2);
}

fn nest(rig: &Rig, levels: usize) {
    let mut dir = rig.seed.join(CARGO_SUBDIR);
    for i in 0..levels {
        dir = dir.join(format!("d{i}"));
    }
    fs::create_dir_all(dir).unwrap();
}

#[test]
fn depth_cap_boundary() {
    let rig = rig();
    nest(&rig, 4);
    let ok = SeedLimits {
        max_depth: 4,
        ..SeedLimits::default()
    };
    warm_job_caches(&rig.seed, &rig.job, ok).unwrap();
    let rig2 = self::rig();
    nest(&rig2, 5);
    let over = SeedLimits {
        max_depth: 4,
        ..SeedLimits::default()
    };
    assert!(matches!(refused(&rig2, over), ToolsError::Seed(_)));
    assert_clean(&rig2);
}

#[test]
fn deep_nesting_is_refused_by_default() {
    let rig = rig();
    nest(&rig, MAX_SEED_DEPTH + 1);
    assert!(matches!(
        refused(&rig, SeedLimits::default()),
        ToolsError::Seed(_)
    ));
}

const _: () = assert!(MAX_SEED_FILE_BYTES <= MAX_SEED_BYTES);

#[test]
fn default_limits_use_the_named_constants() {
    let limits = SeedLimits::default();
    assert_eq!(limits.max_bytes, MAX_SEED_BYTES);
    assert_eq!(limits.max_entries, MAX_SEED_ENTRIES);
    assert_eq!(limits.max_depth, MAX_SEED_DEPTH);
    assert_eq!(limits.max_file_bytes, MAX_SEED_FILE_BYTES);
}

#[test]
fn env_names_point_at_the_copy_never_the_seed() {
    let rig = rig();
    let warm = warm_job_caches(&rig.seed, &rig.job, SeedLimits::default()).unwrap();
    let env = warm.env().unwrap();
    assert_eq!(env[0].0, "CARGO_HOME");
    assert_eq!(env[1].0, "npm_config_cache");
    assert_eq!(Path::new(&env[0].1), warm.cargo_home());
    assert_eq!(Path::new(&env[1].1), warm.npm_cache());
    assert!(
        env.iter()
            .all(|(_, v)| !Path::new(v).starts_with(&rig.seed))
    );
}

#[test]
fn cache_env_is_pure_and_validates() {
    let env = cache_env(Path::new("/j/cargo"), Path::new("/j/npm")).unwrap();
    assert_eq!(
        env,
        [
            ("CARGO_HOME", "/j/cargo".to_owned()),
            ("npm_config_cache", "/j/npm".to_owned())
        ]
    );
    for bad in ["rel/path", "/j/a\nb", "/j/a\0b", ""] {
        assert!(matches!(
            cache_env(Path::new(bad), Path::new("/j/npm")),
            Err(ToolsError::Seed(_))
        ));
        assert!(matches!(
            cache_env(Path::new("/j/cargo"), Path::new(bad)),
            Err(ToolsError::Seed(_))
        ));
    }
}

fn deploy_file(name: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy");
    fs::read_to_string(root.join(name)).unwrap()
}

#[test]
fn tmpfiles_makes_the_seed_fleetd_owned_and_group_read_only() {
    let tmpfiles = deploy_file("tmpfiles.d/fleet.conf");
    for dir in ["seed", "seed/cargo", "seed/npm"] {
        let want = format!("d /var/lib/fleet/{dir} 0750 fleetd fleet-work -");
        assert!(tmpfiles.lines().any(|l| l == want), "{want}");
    }
}

#[test]
fn agent_unit_mounts_the_seed_read_only_and_never_writable() {
    let agent = deploy_file("fleet-agent@.service");
    assert!(
        agent
            .lines()
            .any(|l| l == "ReadOnlyPaths=-/var/lib/fleet/seed")
    );
    for unit in [agent, deploy_file("fleet-tool-install@.service")] {
        let writable = unit
            .lines()
            .filter(|l| l.starts_with("ReadWritePaths="))
            .any(|l| l.contains("/var/lib/fleet/seed"));
        assert!(!writable);
    }
}

#[test]
fn existing_cargo_home_is_refused_and_left_intact() {
    let rig = rig();
    let cargo = rig.job.join(CARGO_HOME_DIR);
    fs::create_dir(&cargo).unwrap();
    fs::write(cargo.join("sentinel"), b"keep").unwrap();
    let err = refused(&rig, SeedLimits::default());
    assert!(matches!(err, ToolsError::Io(_)));
    assert_eq!(fs::read(cargo.join("sentinel")).unwrap(), b"keep");
    assert!(!rig.job.join(NPM_CACHE_DIR).exists());
}

#[test]
fn existing_npm_cache_is_refused_and_only_new_cargo_home_removed() {
    let rig = rig();
    let npm = rig.job.join(NPM_CACHE_DIR);
    fs::create_dir(&npm).unwrap();
    fs::write(npm.join("sentinel"), b"keep").unwrap();
    let err = refused(&rig, SeedLimits::default());
    assert!(matches!(err, ToolsError::Io(_)));
    assert_eq!(fs::read(npm.join("sentinel")).unwrap(), b"keep");
    assert!(!rig.job.join(CARGO_HOME_DIR).exists());
}

#[test]
fn existing_npm_cache_is_left_intact_with_absent_seed() {
    let tmp = TempDir::new().unwrap();
    let job = tmp.path().join("job");
    fs::create_dir(&job).unwrap();
    let npm = job.join(NPM_CACHE_DIR);
    fs::create_dir(&npm).unwrap();
    fs::write(npm.join("sentinel"), b"keep").unwrap();
    let err = warm_job_caches(&tmp.path().join("absent"), &job, SeedLimits::default()).unwrap_err();
    assert!(matches!(err, ToolsError::Io(_)));
    assert_eq!(fs::read(npm.join("sentinel")).unwrap(), b"keep");
    assert!(!job.join(CARGO_HOME_DIR).exists());
}

#[test]
fn mid_tree_failure_removes_the_partial_copy_this_call_made() {
    let rig = rig();
    let deep = rig.seed.join(CARGO_SUBDIR).join("registry").join("sub");
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("big"), vec![0u8; 64]).unwrap();
    let limits = SeedLimits {
        max_file_bytes: 32,
        ..SeedLimits::default()
    };
    let err = refused(&rig, limits);
    assert!(matches!(err, ToolsError::Seed(_)));
    assert_clean(&rig);
}
