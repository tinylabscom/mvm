---
title: Docs for agents
description: Where an LLM or coding agent should start — the generated documentation index, plain-markdown page twins, and a single-page orientation.
template: doc
---

This page used to carry a hand-written index of the docs. It is now generated,
so there is one copy and it cannot fall behind the pages it describes.

## The index

**[/llms.txt](/llms.txt)** is the canonical machine-readable index. It is built
from the content collection at build time and lists every documentation page —
grouped under the same headings as the sidebar, in the same order — with the
page's own one-line description. A page with no description fails the site
build rather than landing in the index as a bare path.

## Plain markdown

Every page is also served as markdown with no navigation chrome: take the page
path, drop the trailing slash, append `.md`. So
[/guides/builder-vm/](/guides/builder-vm/) is also available at
[/guides/builder-vm.md](/guides/builder-vm.md). Each one opens with the page
title, its description, and a pointer back to the index.

## Orientation

**[/skill.md](/skill.md)** (identically, [/agents.md](/agents.md)) is one
copy-pasteable page covering what mvm is, how to install it, how to verify the
host with `mvmctl doctor`, and the shortest path to running a workload. Start
there if you are wiring mvm into an agent rather than reading the docs
end to end.

`mvmctl plugin install` writes the integration file for a supported coding
agent directly into a project; run `mvmctl plugin list` to see the targets.

## Claim rules

These govern how the docs make claims, and are worth knowing before you quote
a page back to a user.

- Strong claims need Shipped, Preview, Planned, or Not claimed status.
- Runtime SDK lifecycle APIs are partial until shared SDK tests cover the full lifecycle.
- OCI examples should use digest-pinned or clearly local/dev references.
- Secret examples should use references or redacted example values, not plaintext credentials.
