//! Tests for `fleet_core::graph`: the hostile cases of the ralph task checker, a hostile path
//! table, every bound with an input just over it, and the ready rule.

use std::collections::BTreeMap;
use std::error::Error;

use fleet_core::graph::{
    Graph, GraphError, Limit, MAX_DEPENDS, MAX_ERRORS, MAX_ID_BYTES, MAX_MERGEABLE,
    MAX_NODE_SLICES, MAX_NODES, MAX_PATH_BYTES, MAX_PATHS_PER_SLICE, MAX_SLICES, MAX_TOTAL_PATHS,
    Node, PathError, RepoPath, overlap, ready, validate,
};

type Res = Result<(), Box<dyn Error>>;

fn node(id: &str, depends: &[&str], slices: Option<&[&str]>, done: bool) -> Node {
    Node {
        id: id.to_owned(),
        depends: depends.iter().map(|d| (*d).to_owned()).collect(),
        why: if depends.is_empty() {
            String::new()
        } else {
            "because".to_owned()
        },
        slices: slices.map(|s| s.iter().map(|x| (*x).to_owned()).collect()),
        done,
    }
}

fn graph(nodes: Vec<Node>, slices: &[(&str, &[&str])], mergeable: &[&str]) -> Graph {
    let mut map = BTreeMap::new();
    for (name, paths) in slices {
        map.insert(
            (*name).to_owned(),
            paths.iter().map(|p| (*p).to_owned()).collect(),
        );
    }
    Graph {
        nodes,
        slices: map,
        mergeable: mergeable.iter().map(|m| (*m).to_owned()).collect(),
    }
}

fn errors(g: &Graph) -> Vec<GraphError> {
    validate(g).err().unwrap_or_default()
}

fn rp(raw: &str) -> Result<RepoPath, PathError> {
    RepoPath::new(raw)
}

fn ov(a: &str, b: &str) -> Result<bool, PathError> {
    Ok(overlap(&rp(a)?, &rp(b)?))
}

fn ready_ids(g: &Graph, running: &[&str]) -> Vec<String> {
    ready(g, running).into_iter().map(str::to_owned).collect()
}

#[test]
fn path_hostile_table_is_rejected_with_the_exact_reason() {
    let long = "a".repeat(MAX_PATH_BYTES + 1);
    let table: Vec<(&str, PathError)> = vec![
        ("", PathError::Empty),
        (".", PathError::DotSegment),
        ("..", PathError::DotSegment),
        ("./a", PathError::DotSegment),
        ("a/./b", PathError::DotSegment),
        ("a/..", PathError::DotSegment),
        ("../a", PathError::DotSegment),
        ("/", PathError::Absolute),
        ("/etc", PathError::Absolute),
        ("//a", PathError::Absolute),
        ("a//b", PathError::EmptySegment),
        ("a//", PathError::EmptySegment),
        ("a\\b", PathError::Backslash),
        ("\\", PathError::Backslash),
        ("a\0b", PathError::Control),
        ("a\rb", PathError::Control),
        ("a\nb", PathError::Control),
        ("a\r\nb", PathError::Control),
        ("a\tb", PathError::Control),
        ("a\x7fb", PathError::Control),
        ("a\u{85}b", PathError::NotAscii),
        ("a\u{2028}b", PathError::NotAscii),
        ("caf\u{e9}", PathError::NotAscii),
        ("\u{202e}a", PathError::NotAscii),
        (long.as_str(), PathError::TooLong),
    ];
    for (raw, want) in table {
        assert_eq!(rp(raw), Err(want), "input {raw:?}");
    }
}

#[test]
fn path_accepts_and_normalises() -> Res {
    assert_eq!(rp("crates/a")?.as_str(), "crates/a");
    assert_eq!(rp("crates/a/")?.as_str(), "crates/a");
    assert_eq!(rp("Cargo.toml")?.as_str(), "Cargo.toml");
    assert_eq!(rp("a b/c")?.as_str(), "a b/c");
    assert_eq!(rp(".github")?.as_str(), ".github");
    assert_eq!(rp("a..b")?.as_str(), "a..b");
    let edge = "a".repeat(MAX_PATH_BYTES);
    assert_eq!(rp(&edge)?.as_str(), edge);
    Ok(())
}

#[test]
fn path_error_display_names_no_input() {
    for e in [
        PathError::Empty,
        PathError::TooLong,
        PathError::Absolute,
        PathError::Backslash,
        PathError::Control,
        PathError::NotAscii,
        PathError::DotSegment,
        PathError::EmptySegment,
    ] {
        assert_ne!(e.to_string(), "");
    }
}

#[test]
fn overlap_is_component_wise_and_symmetric() -> Res {
    let yes = [
        ("crates/a", "crates/a"),
        ("crates/a", "crates/a/"),
        ("crates", "crates/a"),
        ("crates/a", "crates"),
        ("crates/a/src/lib.rs", "crates/a"),
        ("a", "a/b/c"),
        ("Cargo.toml", "Cargo.toml"),
    ];
    for (a, b) in yes {
        assert!(ov(a, b)?, "{a} vs {b}");
        assert!(ov(b, a)?, "{b} vs {a}");
    }
    let no = [
        ("crates/a", "crates/ab"),
        ("crates/ab", "crates/a"),
        ("crates/a", "crates/b"),
        ("Cargo.toml", "Cargo.lock"),
        ("a", "ab/c"),
        ("crates/a/x", "crates/a/y"),
        ("Cargo.toml", "Cargo.toml.bak"),
    ];
    for (a, b) in no {
        assert!(!ov(a, b)?, "{a} vs {b}");
        assert!(!ov(b, a)?, "{b} vs {a}");
    }
    Ok(())
}

#[test]
fn valid_graph_passes() {
    let g = graph(
        vec![
            node("A", &[], Some(&["s1"]), false),
            node("B", &["A"], Some(&["s2"]), false),
        ],
        &[("s1", &["crates/a"]), ("s2", &["crates/ab", "docs"])],
        &["Cargo.lock"],
    );
    assert_eq!(validate(&g), Ok(()));
    assert_eq!(validate(&Graph::default()), Ok(()));
}

#[test]
fn duplicate_id() {
    let g = graph(
        vec![node("A", &[], None, false), node("A", &[], None, false)],
        &[],
        &[],
    );
    assert_eq!(errors(&g), vec![GraphError::DuplicateId("A".to_owned())]);
}

#[test]
fn unknown_depends() {
    let g = graph(vec![node("A", &["GHOST"], None, false)], &[], &[]);
    assert_eq!(
        errors(&g),
        vec![GraphError::UnknownDepends {
            id: "A".to_owned(),
            dep: "GHOST".to_owned()
        }]
    );
}

#[test]
fn depends_without_why() {
    let mut n = node("B", &["A"], None, false);
    n.why = String::new();
    let g = graph(vec![node("A", &[], None, false), n], &[], &[]);
    assert_eq!(errors(&g), vec![GraphError::MissingWhy("B".to_owned())]);
}

#[test]
fn why_without_depends_is_fine() {
    let mut n = node("A", &[], None, false);
    n.why = "unused".to_owned();
    assert_eq!(validate(&graph(vec![n], &[], &[])), Ok(()));
}

#[test]
fn unknown_slice() {
    let g = graph(
        vec![node("A", &[], Some(&["nope"]), false)],
        &[("s", &["a"])],
        &[],
    );
    assert_eq!(
        errors(&g),
        vec![GraphError::UnknownSlice {
            id: "A".to_owned(),
            slice: "nope".to_owned()
        }]
    );
}

#[test]
fn cycle_reports_its_path() {
    let g = graph(
        vec![
            node("A", &["B"], None, false),
            node("B", &["C"], None, false),
            node("C", &["A"], None, false),
        ],
        &[],
        &[],
    );
    assert_eq!(
        errors(&g),
        vec![GraphError::Cycle(vec![
            "A".into(),
            "B".into(),
            "C".into(),
            "A".into()
        ])]
    );
}

#[test]
fn cycle_path_excludes_the_tail_leading_in() {
    let g = graph(
        vec![
            node("T", &["A"], None, false),
            node("A", &["B"], None, false),
            node("B", &["A"], None, false),
        ],
        &[],
        &[],
    );
    assert_eq!(
        errors(&g),
        vec![GraphError::Cycle(vec!["A".into(), "B".into(), "A".into()])]
    );
}

#[test]
fn self_dependency_is_a_cycle() {
    let g = graph(vec![node("A", &["A"], None, false)], &[], &[]);
    assert_eq!(
        errors(&g),
        vec![GraphError::Cycle(vec!["A".into(), "A".into()])]
    );
}

#[test]
fn diamond_is_not_a_cycle() {
    let g = graph(
        vec![
            node("A", &[], None, false),
            node("B", &["A"], None, false),
            node("C", &["A"], None, false),
            node("D", &["B", "C"], None, false),
        ],
        &[],
        &[],
    );
    assert_eq!(validate(&g), Ok(()));
}

#[test]
fn unknown_depends_edge_does_not_hide_a_cycle() {
    let g = graph(
        vec![
            node("A", &["GHOST", "B"], None, false),
            node("B", &["A"], None, false),
        ],
        &[],
        &[],
    );
    let errs = errors(&g);
    assert!(errs.contains(&GraphError::Cycle(vec!["A".into(), "B".into(), "A".into()])));
    assert!(errs.contains(&GraphError::UnknownDepends {
        id: "A".into(),
        dep: "GHOST".into()
    }));
}

#[test]
fn deep_chain_is_iterative() {
    let mut nodes = Vec::new();
    for i in 0..MAX_NODES {
        let id = format!("N{i}");
        if i == 0 {
            nodes.push(node(&id, &[], None, false));
        } else {
            let prev = format!("N{}", i - 1);
            nodes.push(node(&id, &[prev.as_str()], None, false));
        }
    }
    let g = graph(nodes.clone(), &[], &[]);
    assert_eq!(validate(&g), Ok(()));
    let mut ring = nodes;
    ring[0] = node("N0", &[format!("N{}", MAX_NODES - 1).as_str()], None, false);
    ring[0].why = "ring".to_owned();
    let errs = errors(&graph(ring, &[], &[]));
    assert_eq!(errs.len(), 1);
    match errs.first() {
        Some(GraphError::Cycle(path)) => assert_eq!(path.len(), MAX_NODES + 1),
        other => panic!("expected cycle, got {other:?}"),
    }
}

#[test]
fn diamond_ladder_is_linear_not_exponential() {
    let layers = 40;
    let mut nodes = vec![node("L0", &[], None, false)];
    for i in 0..layers {
        let top = format!("L{i}");
        nodes.push(node(&format!("L{i}a"), &[top.as_str()], None, false));
        nodes.push(node(&format!("L{i}b"), &[top.as_str()], None, false));
        let (a, b) = (format!("L{i}a"), format!("L{i}b"));
        nodes.push(node(
            &format!("L{}", i + 1),
            &[a.as_str(), b.as_str()],
            None,
            false,
        ));
    }
    let started = std::time::Instant::now();
    assert_eq!(validate(&graph(nodes, &[], &[])), Ok(()));
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
}

#[test]
fn slice_overlap_same_path_and_cover() {
    let g = graph(vec![], &[("a", &["crates/x"]), ("b", &["crates/x"])], &[]);
    assert_eq!(
        errors(&g),
        vec![GraphError::SliceOverlap {
            first_slice: "a".into(),
            first_path: "crates/x".into(),
            second_slice: "b".into(),
            second_path: "crates/x".into(),
        }]
    );
    let g = graph(vec![], &[("a", &["crates"]), ("b", &["crates/x/"])], &[]);
    assert_eq!(
        errors(&g),
        vec![GraphError::SliceOverlap {
            first_slice: "a".into(),
            first_path: "crates".into(),
            second_slice: "b".into(),
            second_path: "crates/x".into(),
        }]
    );
}

#[test]
fn slice_overlap_within_one_slice_is_reported() {
    let g = graph(vec![], &[("a", &["crates", "crates/x"])], &[]);
    assert_eq!(errors(&g).len(), 1);
}

#[test]
fn sibling_prefix_slices_do_not_overlap() {
    let g = graph(vec![], &[("a", &["crates/a"]), ("b", &["crates/ab"])], &[]);
    assert_eq!(validate(&g), Ok(()));
}

#[test]
fn mergeable_inside_a_slice() {
    let g = graph(vec![], &[("a", &["crates/x"])], &["crates/x/src/lib.rs"]);
    assert_eq!(
        errors(&g),
        vec![GraphError::MergeableInSlice {
            path: "crates/x/src/lib.rs".into(),
            slice: "a".into(),
            slice_path: "crates/x".into(),
        }]
    );
}

#[test]
fn mergeable_covering_a_slice() {
    let g = graph(vec![], &[("a", &["crates/x"])], &["crates"]);
    assert_eq!(errors(&g).len(), 1);
}

#[test]
fn mergeable_equal_to_a_slice_path() {
    let g = graph(vec![], &[("a", &["Cargo.lock"])], &["Cargo.lock/"]);
    assert_eq!(errors(&g).len(), 1);
}

#[test]
fn mergeable_sibling_prefix_is_outside() {
    let g = graph(
        vec![],
        &[("a", &["crates/a"])],
        &["crates/ab", "Cargo.lock"],
    );
    assert_eq!(validate(&g), Ok(()));
}

#[test]
fn hostile_slice_path_is_bad_path_not_echoed() {
    let g = graph(vec![], &[("a", &["ok", "../etc"])], &[]);
    assert_eq!(
        errors(&g),
        vec![GraphError::BadPath {
            slice: Some("a".into()),
            index: 1,
            reason: PathError::DotSegment,
        }]
    );
    let g = graph(vec![], &[("a", &["a\r\nb"])], &[]);
    assert_eq!(
        errors(&g),
        vec![GraphError::BadPath {
            slice: Some("a".into()),
            index: 0,
            reason: PathError::Control
        }]
    );
}

#[test]
fn hostile_mergeable_path_is_bad_path() {
    let g = graph(vec![], &[], &["/abs", "fine"]);
    assert_eq!(
        errors(&g),
        vec![GraphError::BadPath {
            slice: None,
            index: 0,
            reason: PathError::Absolute
        }]
    );
}

#[test]
fn invalid_path_is_skipped_in_overlap_checks() {
    let g = graph(vec![], &[("a", &["x//y"]), ("b", &["x//y"])], &[]);
    assert_eq!(errors(&g).len(), 2);
    assert!(
        errors(&g)
            .iter()
            .all(|e| matches!(e, GraphError::BadPath { .. }))
    );
}

#[test]
fn hostile_ids_are_bad_id_with_index_only() {
    let long = "x".repeat(MAX_ID_BYTES + 1);
    let hostile = [
        "",
        "a b",
        "a\nb",
        "a\u{2028}",
        "caf\u{e9}",
        long.as_str(),
        "a\0",
    ];
    for h in hostile {
        let g = graph(
            vec![node("ok", &[], None, false), node(h, &[], None, false)],
            &[],
            &[],
        );
        assert_eq!(errors(&g), vec![GraphError::BadId { node: 1 }], "id {h:?}");
    }
    let edge = "x".repeat(MAX_ID_BYTES);
    assert_eq!(
        validate(&graph(vec![node(&edge, &[], None, false)], &[], &[])),
        Ok(())
    );
}

#[test]
fn hostile_depends_and_slice_refs_are_not_echoed() {
    let g = graph(vec![node("A", &["x\ny"], None, false)], &[], &[]);
    assert_eq!(
        errors(&g),
        vec![GraphError::BadDepends {
            id: "A".into(),
            index: 0
        }]
    );
    let g = graph(
        vec![node("A", &[], Some(&["ok", "x y"]), false)],
        &[("ok", &["p"])],
        &[],
    );
    assert_eq!(
        errors(&g),
        vec![GraphError::BadSliceRef {
            id: "A".into(),
            index: 1
        }]
    );
}

#[test]
fn hostile_slice_name_is_bad_slice_name() {
    let g = graph(vec![], &[("a", &["p"]), ("b c", &["q"])], &[]);
    assert_eq!(errors(&g), vec![GraphError::BadSliceName { index: 1 }]);
}

#[test]
fn error_messages_never_hold_control_characters() {
    let g = graph(
        vec![node("A\r\nB", &["x\ny"], Some(&["s\0"]), false)],
        &[("n\ra", &["../\n"])],
        &["\u{2028}"],
    );
    for e in errors(&g) {
        let text = e.to_string();
        assert!(!text.chars().any(char::is_control), "{text:?}");
        assert_ne!(text, "");
    }
}

fn many_nodes(n: usize) -> Vec<Node> {
    (0..n)
        .map(|i| node(&format!("N{i}"), &[], None, false))
        .collect()
}

#[test]
fn node_bound() {
    assert_eq!(validate(&graph(many_nodes(MAX_NODES), &[], &[])), Ok(()));
    assert_eq!(
        errors(&graph(many_nodes(MAX_NODES + 1), &[], &[])),
        vec![GraphError::Limit(Limit::Nodes)]
    );
}

#[test]
fn depends_bound() {
    let deps: Vec<String> = (0..=MAX_DEPENDS).map(|i| format!("D{i}")).collect();
    let mut nodes: Vec<Node> = deps.iter().map(|d| node(d, &[], None, false)).collect();
    let refs: Vec<&str> = deps.iter().map(String::as_str).collect();
    nodes.push(node(
        "TOP",
        refs.get(..MAX_DEPENDS).unwrap_or_default(),
        None,
        false,
    ));
    assert_eq!(validate(&graph(nodes.clone(), &[], &[])), Ok(()));
    nodes.pop();
    nodes.push(node("TOP", &refs, None, false));
    assert_eq!(
        errors(&graph(nodes, &[], &[])),
        vec![GraphError::Limit(Limit::Depends)]
    );
}

#[test]
fn node_slices_bound() {
    let names: Vec<String> = (0..=MAX_NODE_SLICES).map(|i| format!("s{i}")).collect();
    let pairs: Vec<(String, String)> = names.iter().map(|n| (n.clone(), format!("p{n}"))).collect();
    let slices: Vec<(&str, Vec<&str>)> = pairs
        .iter()
        .map(|(n, p)| (n.as_str(), vec![p.as_str()]))
        .collect();
    let slice_refs: Vec<(&str, &[&str])> = slices.iter().map(|(n, p)| (*n, p.as_slice())).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let ok = graph(
        vec![node(
            "A",
            &[],
            Some(refs.get(..MAX_NODE_SLICES).unwrap_or_default()),
            false,
        )],
        &slice_refs,
        &[],
    );
    assert_eq!(validate(&ok), Ok(()));
    let over = graph(vec![node("A", &[], Some(&refs), false)], &slice_refs, &[]);
    assert_eq!(errors(&over), vec![GraphError::Limit(Limit::NodeSlices)]);
}

#[test]
fn slice_count_bound() {
    let names: Vec<String> = (0..=MAX_SLICES).map(|i| format!("s{i}")).collect();
    let mut g = Graph::default();
    for n in names.iter().take(MAX_SLICES) {
        g.slices.insert(n.clone(), vec![format!("p{n}")]);
    }
    assert_eq!(validate(&g), Ok(()));
    if let Some(n) = names.last() {
        g.slices.insert(n.clone(), vec![format!("p{n}")]);
    }
    assert_eq!(errors(&g), vec![GraphError::Limit(Limit::Slices)]);
}

#[test]
fn paths_per_slice_bound() {
    let mut g = Graph::default();
    g.slices.insert(
        "a".into(),
        (0..MAX_PATHS_PER_SLICE).map(|i| format!("p{i}")).collect(),
    );
    assert_eq!(validate(&g), Ok(()));
    g.slices.insert(
        "a".into(),
        (0..=MAX_PATHS_PER_SLICE).map(|i| format!("p{i}")).collect(),
    );
    assert_eq!(errors(&g), vec![GraphError::Limit(Limit::PathsPerSlice)]);
}

#[test]
fn total_paths_bound() {
    let per = MAX_PATHS_PER_SLICE;
    let slices_needed = MAX_TOTAL_PATHS / per;
    let mut g = Graph::default();
    for s in 0..slices_needed {
        g.slices.insert(
            format!("s{s}"),
            (0..per).map(|i| format!("d{s}/p{i}")).collect(),
        );
    }
    assert_eq!(validate(&g), Ok(()));
    g.slices.insert("extra".into(), vec!["extra/p".into()]);
    assert_eq!(errors(&g), vec![GraphError::Limit(Limit::TotalPaths)]);
}

#[test]
fn mergeable_bound() {
    let mut g = Graph {
        mergeable: (0..MAX_MERGEABLE).map(|i| format!("m{i}")).collect(),
        ..Graph::default()
    };
    assert_eq!(validate(&g), Ok(()));
    g.mergeable.push("one-more".into());
    assert_eq!(errors(&g), vec![GraphError::Limit(Limit::Mergeable)]);
}

#[test]
fn error_list_is_capped_and_marked() {
    let g = graph(
        (0..MAX_ERRORS + 50)
            .map(|i| node(&format!("N{i}"), &["GHOST"], None, false))
            .collect(),
        &[],
        &[],
    );
    let errs = errors(&g);
    assert_eq!(errs.len(), MAX_ERRORS + 1);
    assert_eq!(errs.last(), Some(&GraphError::Truncated));
    let exact = graph(
        (0..MAX_ERRORS)
            .map(|i| node(&format!("N{i}"), &["GHOST"], None, false))
            .collect(),
        &[],
        &[],
    );
    let errs = errors(&exact);
    assert_eq!(errs.len(), MAX_ERRORS);
    assert!(!errs.contains(&GraphError::Truncated));
}

#[test]
fn ready_basic_dependency_flow() {
    let g = graph(
        vec![
            node("A", &[], Some(&[]), false),
            node("B", &["A"], Some(&[]), false),
            node("C", &[], Some(&[]), true),
        ],
        &[],
        &[],
    );
    assert_eq!(ready_ids(&g, &[]), vec!["A"]);
    let g = graph(
        vec![
            node("A", &[], Some(&[]), true),
            node("B", &["A"], Some(&[]), false),
            node("C", &["A", "B"], Some(&[]), false),
        ],
        &[],
        &[],
    );
    assert_eq!(ready_ids(&g, &[]), vec!["B"]);
}

#[test]
fn ready_keeps_node_order() {
    let g = graph(
        vec![
            node("Z", &[], Some(&[]), false),
            node("M", &[], Some(&[]), false),
            node("A", &[], Some(&[]), false),
        ],
        &[],
        &[],
    );
    assert_eq!(ready_ids(&g, &[]), vec!["Z", "M", "A"]);
    assert_eq!(ready_ids(&g, &[]), ready_ids(&g, &[]));
}

#[test]
fn ready_excludes_running_nodes() {
    let g = graph(
        vec![
            node("A", &[], Some(&[]), false),
            node("B", &[], Some(&[]), false),
        ],
        &[],
        &[],
    );
    assert_eq!(ready_ids(&g, &["A"]), vec!["B"]);
}

#[test]
fn ready_blocks_on_a_shared_slice() {
    let g = graph(
        vec![
            node("A", &[], Some(&["s1"]), false),
            node("B", &[], Some(&["s1", "s2"]), false),
            node("C", &[], Some(&["s3"]), false),
        ],
        &[("s1", &["a"]), ("s2", &["b"]), ("s3", &["c"])],
        &[],
    );
    assert_eq!(ready_ids(&g, &["A"]), vec!["C"]);
    assert_eq!(ready_ids(&g, &[]), vec!["A", "B", "C"]);
}

#[test]
fn ready_empty_slices_own_none() {
    let g = graph(
        vec![
            node("R", &[], Some(&["s1"]), false),
            node("E", &[], Some(&[]), false),
            node("S", &[], Some(&["s1"]), false),
        ],
        &[("s1", &["a"])],
        &[],
    );
    assert_eq!(ready_ids(&g, &["R"]), vec!["E"]);
    let g = graph(
        vec![
            node("R", &[], Some(&[]), false),
            node("E", &[], Some(&[]), false),
            node("W", &[], None, false),
        ],
        &[],
        &[],
    );
    assert_eq!(ready_ids(&g, &["R"]), vec!["E", "W"]);
}

#[test]
fn ready_missing_slices_own_all() {
    let g = graph(
        vec![
            node("W", &[], None, false),
            node("S", &[], Some(&["s1"]), false),
            node("E", &[], Some(&[]), false),
            node("W2", &[], None, false),
        ],
        &[("s1", &["a"])],
        &[],
    );
    assert_eq!(ready_ids(&g, &["W"]), vec!["E"]);
    assert_eq!(ready_ids(&g, &["S"]), vec!["E"]);
}

#[test]
fn ready_is_empty_when_a_running_id_is_unknown() {
    let g = graph(vec![node("A", &[], Some(&[]), false)], &[], &[]);
    assert_eq!(ready_ids(&g, &["GHOST"]), Vec::<String>::new());
    assert_eq!(ready_ids(&g, &["A\n"]), Vec::<String>::new());
}

#[test]
fn ready_is_empty_for_an_invalid_graph() {
    let cyc = graph(
        vec![
            node("A", &["B"], Some(&[]), false),
            node("B", &["A"], Some(&[]), false),
        ],
        &[],
        &[],
    );
    assert_eq!(ready_ids(&cyc, &[]), Vec::<String>::new());
    let dup = graph(
        vec![
            node("A", &[], Some(&[]), false),
            node("A", &[], Some(&[]), false),
        ],
        &[],
        &[],
    );
    assert_eq!(ready_ids(&dup, &[]), Vec::<String>::new());
    let unknown = graph(vec![node("A", &["GHOST"], Some(&[]), false)], &[], &[]);
    assert_eq!(ready_ids(&unknown, &[]), Vec::<String>::new());
}

#[test]
fn ready_is_empty_when_running_list_is_oversized() {
    let g = graph(
        vec![
            node("A", &[], Some(&[]), false),
            node("B", &[], Some(&[]), false),
        ],
        &[],
        &[],
    );
    let edge = vec!["A"; MAX_NODES];
    assert_eq!(ready_ids(&g, &edge), vec!["B"]);
    let over = vec!["A"; MAX_NODES + 1];
    assert_eq!(ready_ids(&g, &over), Vec::<String>::new());
}

#[test]
fn ready_skips_done_nodes() {
    let g = graph(
        vec![
            node("A", &[], Some(&["s1"]), true),
            node("B", &[], Some(&["s1"]), false),
        ],
        &[("s1", &["a"])],
        &[],
    );
    assert_eq!(ready_ids(&g, &[]), vec!["B"]);
}
