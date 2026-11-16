#!/usr/bin/env python3
"""Replay a design snapshot, not source extraction, compilation or acceptance."""

import argparse
import json
from pathlib import Path


def topological_order(edges):
    graph = {}
    degree = {}
    for source, destination in edges:
        graph.setdefault(source, set())
        graph.setdefault(destination, set())
        degree.setdefault(source, 0)
        degree.setdefault(destination, 0)
        if destination not in graph[source]:
            graph[source].add(destination)
            degree[destination] += 1
    ready = sorted(node for node, count in degree.items() if count == 0)
    order = []
    while ready:
        node = ready.pop()
        order.append(node)
        for destination in sorted(graph[node]):
            degree[destination] -= 1
            if degree[destination] == 0:
                ready.append(destination)
    if len(order) != len(graph):
        raise ValueError("cycle in snapshot: " + ", ".join(
            sorted(node for node, count in degree.items() if count)
        ))
    return order


def validate(snapshot):
    if snapshot["schema"] != 1 or snapshot["status"] != "conditional-design-model":
        raise ValueError("not a supported conditional design snapshot")
    if snapshot["acceptance_gate_cleared"] or snapshot["adr_status"] != "Proposed":
        raise ValueError("snapshot replay cannot grant ADR acceptance")
    cases = snapshot["cases"]
    if not cases or len({(row[0], row[1]) for row in cases}) != len(cases):
        raise ValueError("empty or duplicated case matrix")
    limit = (1 << len(cases)) - 1
    edges = []
    seen = set()
    for source, destination, combined_hex, source_hex in snapshot["edges"]:
        pair = (source, destination)
        combined, source_mask = int(combined_hex, 16), int(source_hex, 16)
        if pair in seen or combined <= 0 or combined & ~limit:
            raise ValueError("duplicate edge or invalid case mask")
        if source_mask < 0 or source_mask & ~combined:
            raise ValueError("source edge is not in the combined graph")
        seen.add(pair)
        edges.append((pair, combined, source_mask))
    union = topological_order(pair for pair, _, _ in edges)
    for index, (target, profile, source_count, node_count, edge_count) in enumerate(cases):
        bit = 1 << index
        selected = [pair for pair, combined, _ in edges if combined & bit]
        source_edges = [pair for pair, _, source_mask in edges if source_mask & bit]
        order = topological_order(selected)
        topological_order(source_edges)
        if (len(source_edges), len(order), len(selected)) != (
            source_count, node_count, edge_count
        ):
            raise ValueError(f"count mismatch for {target}/{profile}")
    return len(cases), len(union), len(edges)


def self_test(snapshot):
    if topological_order([("caller", "owner")]) != ["caller", "owner"]:
        raise AssertionError("dependency direction changed")
    for cycle in [[("a", "a")], [("a", "b"), ("b", "a")]]:
        try:
            topological_order(cycle)
        except ValueError:
            pass
        else:
            raise AssertionError("cycle was accepted")
    for corrupt in (
        lambda data: data["edges"].append(data["edges"][0]),
        lambda data: data["edges"][0].__setitem__(3, "1" + "0" * 20),
        lambda data: data.__setitem__("acceptance_gate_cleared", True),
        lambda data: data["cases"][0].__setitem__(2, -1),
    ):
        broken = json.loads(json.dumps(snapshot))
        corrupt(broken)
        try:
            validate(broken)
        except ValueError:
            pass
        else:
            raise AssertionError("corrupt snapshot was accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    snapshot = json.loads(Path(__file__).with_name("graph.json").read_text())
    if args.self_test:
        self_test(snapshot)
        print("Replay negative fixtures passed")
    cases, nodes, edges = validate(snapshot)
    print(f"Conditional snapshot: {cases} cases and union ({nodes} nodes/{edges} edges) acyclic")
    print("Not checked: current source, compiler resolution, API privacy, behavior or acceptance")


if __name__ == "__main__":
    main()
