---
title: "Density RSS rows and macOS idle wakeups: classify by program file name, and count kernel wakeups"
author: Ari
date: 2026-11-13
branch: main
cost: { minutes: 10, tokens: 156087 }
id: l-ac74b45d
scope: repo
status: active
src: agent
touches:
  - scripts/measure-hvf-density.sh
---

## Decided
The density RSS table must name a process by argv[0]'s file name only. The default output directory contains the backend name, so matching the whole ps line counted every helper as the VMM. The macOS idle sampler reads libproc via ctypes and counts wakeups as ri_pkg_idle_wkups + ri_interrupt_wkups.

## Tried and ruled out
On this Mac ri_pkg_idle_wkups stayed 0 for a process doing 300 timer sleeps while ri_interrupt_wkups rose by 301, so the interrupt count has to be included. pti_csw counts all context switches, not only voluntary ones, so it was not used. An awk program held in single quotes breaks on an apostrophe in a comment, and shellcheck reports it as a parse error far from the cause.

## Watch out
A red "lane is red" issue is not closed by a manual dispatch going green. Check the newest scheduled run: Pack signing smoke is green on dispatch (43387980923) but its last scheduled run (43367427050) failed. Wakeup figures from macOS and Linux are different quantities and must not be compared as equals. A load average above 70 on this Mac makes any latency bench non-evidence.

In the code: scripts/density_idle.py (Libproc, sample_macos), scripts/measure-hvf-density.sh (capture_processes).
