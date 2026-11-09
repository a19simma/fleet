//! Work graph: tasks with dependencies, slices of repo paths, and a mergeable path list.
//! Performs no IO.
//!
//! [`validate`] checks a [`Graph`] and reports every problem it finds. [`ready`] lists the
//! nodes that may start. Every string is untrusted: ids, slice names and paths are checked
//! before they are compared, and errors carry only values that passed that check or an index.
//!
//! | Bound | Constant |
//! |---|---|
//! | nodes | [`MAX_NODES`] |
//! | id and slice name length | [`MAX_ID_BYTES`] |
//! | depends per node | [`MAX_DEPENDS`] |
//! | slices per node | [`MAX_NODE_SLICES`] |
//! | slices | [`MAX_SLICES`] |
//! | paths per slice | [`MAX_PATHS_PER_SLICE`] |
//! | paths over all slices | [`MAX_TOTAL_PATHS`] |
//! | mergeable paths | [`MAX_MERGEABLE`] |
//! | path length | [`MAX_PATH_BYTES`] |
//! | errors returned | [`MAX_ERRORS`] |

use std::collections::{BTreeMap, HashMap};
use std::fmt;

/// Most nodes in one graph.
pub const MAX_NODES: usize = 4096;
/// Longest accepted id or slice name, in bytes.
pub const MAX_ID_BYTES: usize = 128;
/// Most `depends` entries on one node.
pub const MAX_DEPENDS: usize = 64;
/// Most slice names on one node.
pub const MAX_NODE_SLICES: usize = 32;
/// Most slices in one graph.
pub const MAX_SLICES: usize = 256;
/// Most paths in one slice.
pub const MAX_PATHS_PER_SLICE: usize = 64;
/// Most paths over all slices.
pub const MAX_TOTAL_PATHS: usize = 2048;
/// Most mergeable paths.
pub const MAX_MERGEABLE: usize = 256;
/// Longest accepted path, in bytes.
pub const MAX_PATH_BYTES: usize = 512;
/// Most errors [`validate`] returns before it adds [`GraphError::Truncated`].
pub const MAX_ERRORS: usize = 256;

/// Why a string is not a [`RepoPath`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathError {
    /// The path is empty.
    Empty,
    /// The path is over [`MAX_PATH_BYTES`].
    TooLong,
    /// The path starts with `/`.
    Absolute,
    /// The path holds a backslash.
    Backslash,
    /// The path holds an ASCII control character.
    Control,
    /// The path holds a byte outside ASCII.
    NotAscii,
    /// A segment is `.` or `..`.
    DotSegment,
    /// A segment is empty, as in `a//b`.
    EmptySegment,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "path is empty",
            Self::TooLong => "path is too long",
            Self::Absolute => "path is absolute",
            Self::Backslash => "path holds a backslash",
            Self::Control => "path holds a control character",
            Self::NotAscii => "path holds a non-ASCII character",
            Self::DotSegment => "path holds a dot segment",
            Self::EmptySegment => "path holds an empty segment",
        })
    }
}

impl std::error::Error for PathError {}

/// A relative, normalised path of printable ASCII segments.
///
/// One trailing `/` is dropped. A path names a file or a directory and covers everything
/// below it. Comparison is case-sensitive and nothing is percent-decoded, so a consumer must
/// not case-fold or decode a path before it compares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoPath {
    text: String,
}

impl RepoPath {
    /// Check and normalise `raw`.
    ///
    /// # Errors
    ///
    /// Returns the first [`PathError`] that applies: length, control characters, backslash,
    /// non-ASCII, leading `/`, empty or dot segments.
    pub fn new(raw: &str) -> Result<Self, PathError> {
        if raw.is_empty() {
            return Err(PathError::Empty);
        }
        if raw.len() > MAX_PATH_BYTES {
            return Err(PathError::TooLong);
        }
        for c in raw.chars() {
            if !c.is_ascii() {
                return Err(PathError::NotAscii);
            }
            if c.is_ascii_control() {
                return Err(PathError::Control);
            }
            if c == '\\' {
                return Err(PathError::Backslash);
            }
        }
        if raw.starts_with('/') {
            return Err(PathError::Absolute);
        }
        let trimmed = raw.strip_suffix('/').unwrap_or(raw);
        for segment in trimmed.split('/') {
            if segment.is_empty() {
                return Err(PathError::EmptySegment);
            }
            if segment == "." || segment == ".." {
                return Err(PathError::DotSegment);
            }
        }
        Ok(Self {
            text: trimmed.to_owned(),
        })
    }

    /// The normalised text.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    fn segments(&self) -> impl Iterator<Item = &str> {
        self.text.split('/')
    }
}

/// Whether one path covers the other, compared by segments.
///
/// Equal paths overlap, a directory overlaps everything under it, and `crates/a` does not
/// overlap `crates/ab`.
pub fn overlap(a: &RepoPath, b: &RepoPath) -> bool {
    a.segments().zip(b.segments()).all(|(x, y)| x == y)
}

/// A bound a graph went over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Limit {
    /// More than [`MAX_NODES`] nodes.
    Nodes,
    /// A node with more than [`MAX_DEPENDS`] depends.
    Depends,
    /// A node with more than [`MAX_NODE_SLICES`] slices.
    NodeSlices,
    /// More than [`MAX_SLICES`] slices.
    Slices,
    /// A slice with more than [`MAX_PATHS_PER_SLICE`] paths.
    PathsPerSlice,
    /// More than [`MAX_TOTAL_PATHS`] paths over all slices.
    TotalPaths,
    /// More than [`MAX_MERGEABLE`] mergeable paths.
    Mergeable,
}

/// One problem [`validate`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GraphError {
    /// A bound was passed. No other check ran.
    Limit(Limit),
    /// The node at this position has an invalid id.
    BadId {
        /// Position in [`Graph::nodes`].
        node: usize,
    },
    /// A depends entry of this node is not a valid id.
    BadDepends {
        /// The node.
        id: String,
        /// Position in the node's depends.
        index: usize,
    },
    /// A slice name of this node is not a valid name.
    BadSliceRef {
        /// The node.
        id: String,
        /// Position in the node's slices.
        index: usize,
    },
    /// The slice at this position, in name order, has an invalid name.
    BadSliceName {
        /// Position in name order.
        index: usize,
    },
    /// A path failed [`RepoPath::new`].
    BadPath {
        /// The slice, or `None` for the mergeable list.
        slice: Option<String>,
        /// Position in that slice or in the mergeable list.
        index: usize,
        /// Why it failed.
        reason: PathError,
    },
    /// Two nodes share an id.
    DuplicateId(String),
    /// A node depends on an id no node has.
    UnknownDepends {
        /// The node.
        id: String,
        /// The missing id.
        dep: String,
    },
    /// A node has depends and an empty `why`.
    MissingWhy(String),
    /// A node names a slice that does not exist.
    UnknownSlice {
        /// The node.
        id: String,
        /// The missing slice.
        slice: String,
    },
    /// Depends form a loop. The path starts and ends on the same id.
    Cycle(Vec<String>),
    /// Two slice paths cover one another.
    SliceOverlap {
        /// First slice in name order.
        first_slice: String,
        /// Its path.
        first_path: String,
        /// Second slice.
        second_slice: String,
        /// Its path.
        second_path: String,
    },
    /// A mergeable path overlaps a slice path.
    MergeableInSlice {
        /// The mergeable path.
        path: String,
        /// The slice.
        slice: String,
        /// The slice path it overlaps.
        slice_path: String,
    },
    /// More than [`MAX_ERRORS`] errors were found and the rest were dropped.
    Truncated,
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit(l) => write!(f, "graph is over a limit: {l:?}"),
            Self::BadId { node } => write!(f, "node {node}: invalid id"),
            Self::BadDepends { id, index } => write!(f, "{id}: depends {index} is not a valid id"),
            Self::BadSliceRef { id, index } => write!(f, "{id}: slice {index} is not a valid name"),
            Self::BadSliceName { index } => write!(f, "slice {index}: invalid name"),
            Self::BadPath {
                slice,
                index,
                reason,
            } => match slice {
                Some(s) => write!(f, "slice {s}: path {index}: {reason}"),
                None => write!(f, "mergeable {index}: {reason}"),
            },
            Self::DuplicateId(id) => write!(f, "duplicate id {id}"),
            Self::UnknownDepends { id, dep } => write!(f, "{id}: depends on unknown id {dep}"),
            Self::MissingWhy(id) => write!(f, "{id}: depends set but why empty"),
            Self::UnknownSlice { id, slice } => write!(f, "{id}: unknown slice {slice}"),
            Self::Cycle(path) => write!(f, "dependency cycle {}", path.join(" -> ")),
            Self::SliceOverlap {
                first_slice,
                first_path,
                second_slice,
                second_path,
            } => write!(
                f,
                "slice overlap {first_slice}:{first_path} and {second_slice}:{second_path}"
            ),
            Self::MergeableInSlice {
                path,
                slice,
                slice_path,
            } => {
                write!(f, "mergeable {path} overlaps {slice}:{slice_path}")
            }
            Self::Truncated => f.write_str("more errors were dropped"),
        }
    }
}

impl std::error::Error for GraphError {}

/// One task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Unique id.
    pub id: String,
    /// Ids that must be done first.
    pub depends: Vec<String>,
    /// Why the depends exist. Required when `depends` is not empty.
    pub why: String,
    /// Slices the node owns. `None` owns every slice and `Some` of an empty list owns none.
    pub slices: Option<Vec<String>>,
    /// Whether the node is finished.
    pub done: bool,
}

/// Nodes, slices and the mergeable path list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Graph {
    /// Nodes in a stable order that [`ready`] keeps.
    pub nodes: Vec<Node>,
    /// Slice name to the paths it owns.
    pub slices: BTreeMap<String, Vec<String>>,
    /// Paths any node may change. None may overlap a slice path.
    pub mergeable: Vec<String>,
}

fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_ID_BYTES && s.bytes().all(|b| b.is_ascii_graphic())
}

struct Sink {
    list: Vec<GraphError>,
    full: bool,
}

impl Sink {
    fn push(&mut self, e: GraphError) {
        if self.list.len() < MAX_ERRORS {
            self.list.push(e);
        } else {
            self.full = true;
        }
    }

    fn finish(mut self) -> Vec<GraphError> {
        if self.full {
            self.list.push(GraphError::Truncated);
        }
        self.list
    }
}

fn limits(graph: &Graph) -> Vec<GraphError> {
    let mut out = Vec::new();
    let mut check = |over: bool, l: Limit| {
        if over {
            out.push(GraphError::Limit(l));
        }
    };
    check(graph.nodes.len() > MAX_NODES, Limit::Nodes);
    check(
        graph.nodes.iter().any(|n| n.depends.len() > MAX_DEPENDS),
        Limit::Depends,
    );
    check(
        graph
            .nodes
            .iter()
            .any(|n| n.slices.as_ref().is_some_and(|s| s.len() > MAX_NODE_SLICES)),
        Limit::NodeSlices,
    );
    check(graph.slices.len() > MAX_SLICES, Limit::Slices);
    check(
        graph.slices.values().any(|p| p.len() > MAX_PATHS_PER_SLICE),
        Limit::PathsPerSlice,
    );
    check(
        graph.slices.values().map(Vec::len).sum::<usize>() > MAX_TOTAL_PATHS,
        Limit::TotalPaths,
    );
    check(graph.mergeable.len() > MAX_MERGEABLE, Limit::Mergeable);
    out
}

fn find_cycle(adj: &[Vec<usize>], ids: &[&str]) -> Option<Vec<String>> {
    let mut colour = vec![0u8; adj.len()];
    for start in 0..adj.len() {
        if let Some(c) = colour.get_mut(start) {
            *c = 1;
        }
        let mut stack: Vec<(usize, usize)> = vec![(start, 0)];
        while let Some(&(node, next)) = stack.last() {
            let edge = adj.get(node).and_then(|e| e.get(next)).copied();
            let Some(to) = edge else {
                if let Some(c) = colour.get_mut(node) {
                    *c = 2;
                }
                stack.pop();
                continue;
            };
            if let Some(top) = stack.last_mut() {
                top.1 += 1;
            }
            match colour.get(to).copied() {
                Some(1) => {
                    let from = stack.iter().position(|&(n, _)| n == to).unwrap_or(0);
                    let mut path: Vec<String> = stack
                        .iter()
                        .skip(from)
                        .filter_map(|&(n, _)| ids.get(n).map(|s| (*s).to_owned()))
                        .collect();
                    path.extend(ids.get(to).map(|s| (*s).to_owned()));
                    return Some(path);
                }
                Some(0) => {
                    if let Some(c) = colour.get_mut(to) {
                        *c = 1;
                    }
                    stack.push((to, 0));
                }
                _ => {}
            }
        }
    }
    None
}

fn check_nodes(graph: &Graph, sink: &mut Sink) {
    let mut index: HashMap<&str, usize> = HashMap::new();
    for (i, n) in graph.nodes.iter().enumerate() {
        if !valid_name(&n.id) {
            sink.push(GraphError::BadId { node: i });
        } else if index.insert(&n.id, i).is_some() {
            sink.push(GraphError::DuplicateId(n.id.clone()));
        }
    }
    let mut adj: Vec<Vec<usize>> = Vec::with_capacity(graph.nodes.len());
    let mut ids: Vec<&str> = Vec::with_capacity(graph.nodes.len());
    for n in &graph.nodes {
        ids.push(&n.id);
        let mut edges = Vec::new();
        let named = valid_name(&n.id);
        for (i, dep) in n.depends.iter().enumerate() {
            if !valid_name(dep) {
                if named {
                    sink.push(GraphError::BadDepends {
                        id: n.id.clone(),
                        index: i,
                    });
                }
            } else if let Some(&to) = index.get(dep.as_str()) {
                edges.push(to);
            } else if named {
                sink.push(GraphError::UnknownDepends {
                    id: n.id.clone(),
                    dep: dep.clone(),
                });
            }
        }
        if named && !n.depends.is_empty() && n.why.is_empty() {
            sink.push(GraphError::MissingWhy(n.id.clone()));
        }
        for (i, s) in n.slices.iter().flatten().enumerate() {
            if !valid_name(s) {
                if named {
                    sink.push(GraphError::BadSliceRef {
                        id: n.id.clone(),
                        index: i,
                    });
                }
            } else if named && !graph.slices.contains_key(s) {
                sink.push(GraphError::UnknownSlice {
                    id: n.id.clone(),
                    slice: s.clone(),
                });
            }
        }
        adj.push(edges);
    }
    if let Some(path) = find_cycle(&adj, &ids) {
        sink.push(GraphError::Cycle(path));
    }
}

fn check_paths(graph: &Graph, sink: &mut Sink) {
    let mut flat: Vec<(&str, RepoPath)> = Vec::new();
    for (si, (name, paths)) in graph.slices.iter().enumerate() {
        let named = valid_name(name);
        if !named {
            sink.push(GraphError::BadSliceName { index: si });
        }
        for (i, raw) in paths.iter().enumerate() {
            match RepoPath::new(raw) {
                Ok(p) if named => flat.push((name, p)),
                Ok(_) => {}
                Err(reason) => sink.push(GraphError::BadPath {
                    slice: named.then(|| name.clone()),
                    index: i,
                    reason,
                }),
            }
        }
    }
    for (i, (n1, p1)) in flat.iter().enumerate() {
        for (n2, p2) in flat.iter().skip(i + 1) {
            if overlap(p1, p2) {
                sink.push(GraphError::SliceOverlap {
                    first_slice: (*n1).to_owned(),
                    first_path: p1.as_str().to_owned(),
                    second_slice: (*n2).to_owned(),
                    second_path: p2.as_str().to_owned(),
                });
            }
        }
    }
    for (i, raw) in graph.mergeable.iter().enumerate() {
        match RepoPath::new(raw) {
            Ok(mp) => {
                for (name, p) in &flat {
                    if overlap(&mp, p) {
                        sink.push(GraphError::MergeableInSlice {
                            path: mp.as_str().to_owned(),
                            slice: (*name).to_owned(),
                            slice_path: p.as_str().to_owned(),
                        });
                    }
                }
            }
            Err(reason) => sink.push(GraphError::BadPath {
                slice: None,
                index: i,
                reason,
            }),
        }
    }
}

/// Check a graph and return every problem found, in a fixed order.
///
/// A graph over a bound returns only [`GraphError::Limit`] entries. Otherwise the checks cover
/// ids, depends, `why`, slice names, dependency cycles, slice path overlap and mergeable paths
/// inside a slice. At most [`MAX_ERRORS`] errors come back, then [`GraphError::Truncated`].
///
/// # Errors
///
/// Returns the list of [`GraphError`] when the graph is not valid.
pub fn validate(graph: &Graph) -> Result<(), Vec<GraphError>> {
    let over = limits(graph);
    if !over.is_empty() {
        return Err(over);
    }
    let mut sink = Sink {
        list: Vec::new(),
        full: false,
    };
    check_nodes(graph, &mut sink);
    check_paths(graph, &mut sink);
    let list = sink.finish();
    if list.is_empty() { Ok(()) } else { Err(list) }
}

enum Owns<'g> {
    Nothing,
    All,
    Some(&'g [String]),
}

fn owns(node: &Node) -> Owns<'_> {
    match &node.slices {
        None => Owns::All,
        Some(s) if s.is_empty() => Owns::Nothing,
        Some(s) => Owns::Some(s),
    }
}

fn conflicts(a: &Owns<'_>, b: &Owns<'_>) -> bool {
    match (a, b) {
        (Owns::Nothing, _) | (_, Owns::Nothing) => false,
        (Owns::All, _) | (_, Owns::All) => true,
        (Owns::Some(x), Owns::Some(y)) => x.iter().any(|s| y.contains(s)),
    }
}

/// Ids of the nodes that may start, in node order.
///
/// A node is ready when it is not done, not in `running`, every dependency is done, and its
/// slices do not conflict with those of a running node. A node without a slice list owns every
/// slice and one with an empty list owns none, so it never conflicts. An invalid graph, a
/// `running` list over [`MAX_NODES`] entries, or a running id no node has returns nothing. A graph
/// with a duplicate id is invalid, so it returns nothing too.
///
/// The returned nodes are checked against `running` only, not against each other, so two of them
/// can conflict. The caller must start one at a time, or call `ready` again after each start.
pub fn ready<'g>(graph: &'g Graph, running: &[&str]) -> Vec<&'g str> {
    if running.len() > MAX_NODES || validate(graph).is_err() {
        return Vec::new();
    }
    let index: HashMap<&str, usize> = graph
        .nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (n.id.as_str(), i))
        .collect();
    let mut held = Vec::new();
    for id in running {
        match index.get(id).and_then(|&i| graph.nodes.get(i)) {
            Some(n) => held.push(owns(n)),
            None => return Vec::new(),
        }
    }
    graph
        .nodes
        .iter()
        .filter(|n| !n.done && !running.contains(&n.id.as_str()))
        .filter(|n| {
            n.depends.iter().all(|d| {
                index
                    .get(d.as_str())
                    .and_then(|&i| graph.nodes.get(i))
                    .is_some_and(|dn| dn.done)
            })
        })
        .filter(|n| {
            let mine = owns(n);
            !held.iter().any(|h| conflicts(&mine, h))
        })
        .map(|n| n.id.as_str())
        .collect()
}
