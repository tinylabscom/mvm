//! The declared edge graph, validated once before anything boots.
//!
//! ## Why a cycle is not merely unsupported
//!
//! A cycle breaks EOF propagation: nothing downstream of itself ever sees its
//! producer close, so it never closes either. With lossy eviction it does not
//! even deadlock into something obvious — it degrades into a silently churning
//! loop that looks like a workload doing work. And every edge hash-chains, so
//! a cycle leaves no order in which to ask what a workload saw.
//!
//! The topology is declared rather than discovered, so this is a cheap static
//! check with nothing to race. It runs before boot and fails closed.
//!
//! ## What this module is not
//!
//! It does not resolve bindings, authorize them, or know what a fleet is. It
//! takes edges already resolved to source workloads and answers one question:
//! is this a DAG. `mvmd` owns the resolution; `mvm` owns the refusal.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

/// One resolved edge: bytes flow from `source` into `consumer`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResolvedEdge {
    /// The workload whose output feeds the edge.
    pub source: String,
    /// The workload whose input the edge writes.
    pub consumer: String,
    /// The consumer-local binding name, carried so a refusal can name the
    /// declaration a human wrote rather than the pair a validator derived.
    pub binding: String,
}

impl ResolvedEdge {
    /// A resolved edge from its three parts.
    #[must_use]
    pub fn new(
        source: impl Into<String>,
        consumer: impl Into<String>,
        binding: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            consumer: consumer.into(),
            binding: binding.into(),
        }
    }
}

/// Why a declared topology was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopologyError {
    /// The graph contains a cycle. `path` is the cycle in flow order, first
    /// node repeated at the end, so an operator can read it as a route.
    Cycle { path: Vec<String> },
    /// Two edges write the same consumer's input.
    ///
    /// E3: one input slot, one writer. Two producers interleaving into one
    /// stdin produce corrupted records, and stdin carries no framing to
    /// recover them. A workflow that needs fan-in declares a merge stage,
    /// which is itself a workload the fleet can express.
    FanIn {
        consumer: String,
        bindings: Vec<String>,
    },
}

impl TopologyError {
    /// An operator-facing description that names the declaration at fault.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Cycle { path } => {
                alloc::format!(
                    "stream edges form a cycle: {} — a cycle never propagates EOF, so nothing \
                     downstream of itself ever closes",
                    path.join(" -> ")
                )
            }
            Self::FanIn { consumer, bindings } => alloc::format!(
                "workload {:?} is fed by {} edges ({}) but has one input slot — declare a merge \
                 stage instead of two writers",
                consumer,
                bindings.len(),
                bindings.join(", ")
            ),
        }
    }
}

/// Validate a declared topology, refusing before anything boots.
///
/// Returns the consumers in a valid start order when the graph is a DAG: a
/// caller that wants to boot producers before consumers can follow it, and a
/// caller that does not can ignore it.
///
/// # Errors
///
/// [`TopologyError::FanIn`] when two edges write one consumer, and
/// [`TopologyError::Cycle`] when flow returns to a workload it already passed
/// through — including the self-edge and cycles of any length.
pub fn validate(edges: &[ResolvedEdge]) -> Result<Vec<String>, TopologyError> {
    // Fan-in first: it is the cheaper question, and a graph that fails it has
    // an ambiguous shape the cycle walk would then be reasoning about.
    let mut writers: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for edge in edges {
        writers
            .entry(edge.consumer.as_str())
            .or_default()
            .push(edge.binding.as_str());
    }
    if let Some((consumer, bindings)) = writers.iter().find(|(_, b)| b.len() > 1) {
        return Err(TopologyError::FanIn {
            consumer: String::from(*consumer),
            bindings: bindings.iter().map(|b| String::from(*b)).collect(),
        });
    }

    let mut out: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut nodes: BTreeSet<&str> = BTreeSet::new();
    for edge in edges {
        out.entry(edge.source.as_str())
            .or_default()
            .push(edge.consumer.as_str());
        nodes.insert(edge.source.as_str());
        nodes.insert(edge.consumer.as_str());
    }

    // Iterative DFS with an explicit on-stack set. Recursion would be simpler
    // and would blow the stack on a long chain, which a fleet can trivially
    // declare.
    let mut done: BTreeSet<&str> = BTreeSet::new();
    let mut order: Vec<String> = Vec::new();
    for root in &nodes {
        if done.contains(root) {
            continue;
        }
        let mut on_path: Vec<&str> = Vec::new();
        let mut on_path_set: BTreeSet<&str> = BTreeSet::new();
        // (node, index of the next child to visit)
        let mut stack: Vec<(&str, usize)> = alloc::vec![(*root, 0)];
        on_path.push(root);
        on_path_set.insert(root);

        while let Some((node, child_idx)) = stack.pop() {
            let children = out.get(node).map(Vec::as_slice).unwrap_or(&[]);
            if child_idx < children.len() {
                stack.push((node, child_idx + 1));
                let child = children[child_idx];
                if on_path_set.contains(child) {
                    // Cycle: report it from where it re-enters, so the path
                    // reads as the loop rather than as the walk that found it.
                    let start = on_path.iter().position(|n| *n == child).unwrap_or(0);
                    let mut path: Vec<String> =
                        on_path[start..].iter().map(|n| String::from(*n)).collect();
                    path.push(String::from(child));
                    return Err(TopologyError::Cycle { path });
                }
                if !done.contains(child) {
                    on_path.push(child);
                    on_path_set.insert(child);
                    stack.push((child, 0));
                }
            } else {
                done.insert(node);
                order.push(String::from(node));
                on_path.pop();
                on_path_set.remove(node);
            }
        }
    }

    // `order` is post-order, so producers land after the consumers they feed.
    // Reverse it to get flow order.
    order.reverse();
    Ok(order)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn edge(source: &str, consumer: &str) -> ResolvedEdge {
        ResolvedEdge::new(source, consumer, alloc::format!("{source}->{consumer}"))
    }

    #[test]
    fn a_chain_is_a_dag_and_comes_back_in_flow_order() {
        let edges = vec![edge("a", "b"), edge("b", "c")];
        let order = validate(&edges).expect("a chain is acyclic");
        let a = order.iter().position(|n| n == "a").expect("a present");
        let b = order.iter().position(|n| n == "b").expect("b present");
        let c = order.iter().position(|n| n == "c").expect("c present");
        assert!(a < b && b < c, "producers precede consumers: {order:?}");
    }

    #[test]
    fn a_fan_out_is_a_dag() {
        // One producer feeding two consumers is fine — it is fan-*in* that E3
        // rules out, and conflating them would refuse a legal topology.
        let edges = vec![edge("a", "b"), edge("a", "c")];
        validate(&edges).expect("one source may feed several consumers");
    }

    #[test]
    fn a_self_edge_is_refused() {
        let err = validate(&[edge("a", "a")]).expect_err("a self-edge is a cycle");
        match err {
            TopologyError::Cycle { path } => assert_eq!(path, vec!["a", "a"]),
            other => panic!("expected a cycle, got {other:?}"),
        }
    }

    #[test]
    fn a_two_node_cycle_is_refused() {
        let err = validate(&[edge("a", "b"), edge("b", "a")]).expect_err("a->b->a is a cycle");
        assert!(matches!(err, TopologyError::Cycle { .. }), "{err:?}");
    }

    /// The usual defect is a validator that only catches `A→A`, so the long
    /// cycle is the one that actually proves the walk works.
    #[test]
    fn a_long_cycle_is_refused() {
        let edges = vec![
            edge("a", "b"),
            edge("b", "c"),
            edge("c", "d"),
            edge("d", "e"),
            edge("e", "a"),
        ];
        let err = validate(&edges).expect_err("a five-node cycle is a cycle");
        match err {
            TopologyError::Cycle { path } => {
                assert_eq!(path.first(), path.last(), "the path closes: {path:?}");
                assert!(path.len() >= 5, "the whole loop is reported: {path:?}");
            }
            other => panic!("expected a cycle, got {other:?}"),
        }
    }

    /// Entering a cycle from outside it is refused — as fan-in, not as a
    /// cycle, and that is not a weaker answer.
    ///
    /// It falls out of E3 rather than being a second rule: one input slot
    /// means one in-edge, so a node reachable both from a prefix and from
    /// around a loop already has two writers. The consequence worth writing
    /// down is that under E3 a cycle can only ever be an isolated loop with no
    /// way in — which is why the cycle walk is checked against disjoint
    /// components below rather than against attached ones, and why refusing
    /// fan-in first is what makes the graph shape simple enough to reason
    /// about at all.
    #[test]
    fn entering_a_cycle_from_outside_it_is_refused_as_fan_in() {
        let edges = vec![edge("root", "a"), edge("a", "b"), edge("b", "a")];
        let err = validate(&edges).expect_err("`a` is written by both root and b");
        match err {
            TopologyError::FanIn { consumer, .. } => assert_eq!(consumer, "a"),
            other => panic!("expected fan-in, got {other:?}"),
        }
    }

    /// Two disjoint components, one clean and one cyclic. A validator that
    /// returned on the first clean root would miss this.
    #[test]
    fn a_cycle_in_a_second_component_is_refused() {
        let edges = vec![edge("a", "b"), edge("x", "y"), edge("y", "x")];
        let err = validate(&edges).expect_err("the second component cycles");
        assert!(matches!(err, TopologyError::Cycle { .. }), "{err:?}");
    }

    #[test]
    fn a_diamond_is_a_dag() {
        // a feeds b and c; both feed different consumers. Not fan-in, and a
        // depth-first walk revisits `a`'s descendants — which must not be
        // mistaken for a cycle.
        let edges = vec![
            edge("a", "b"),
            edge("a", "c"),
            edge("b", "d"),
            edge("c", "e"),
        ];
        validate(&edges).expect("a diamond of distinct consumers is acyclic");
    }

    #[test]
    fn two_writers_for_one_consumer_are_refused() {
        let edges = vec![
            ResolvedEdge::new("a", "sink", "from-a"),
            ResolvedEdge::new("b", "sink", "from-b"),
        ];
        let err = validate(&edges).expect_err("one input slot, one writer");
        match err {
            TopologyError::FanIn { consumer, bindings } => {
                assert_eq!(consumer, "sink");
                assert_eq!(bindings, vec!["from-a", "from-b"]);
            }
            other => panic!("expected fan-in, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_topology_is_valid() {
        assert_eq!(
            validate(&[]).expect("nothing to refuse"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn descriptions_name_the_declaration_at_fault() {
        let cycle = validate(&[edge("a", "b"), edge("b", "a")]).expect_err("cycle");
        let text = cycle.describe();
        assert!(
            text.contains("a -> b -> a") || text.contains("b -> a -> b"),
            "{text}"
        );

        let fan_in = validate(&[
            ResolvedEdge::new("a", "sink", "from-a"),
            ResolvedEdge::new("b", "sink", "from-b"),
        ])
        .expect_err("fan-in");
        let text = fan_in.describe();
        assert!(text.contains("from-a") && text.contains("from-b"), "{text}");
        assert!(text.contains("merge stage"), "the fix is named: {text}");
    }
}
