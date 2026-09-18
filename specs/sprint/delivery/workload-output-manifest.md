# Workload output handback: `--output`, a signed grant, and `plan.outputs`

A transient workload can now hand files back to the host:

    mvmctl machine run --image alpine --output ./results:/data/out:16M \
      -- sh -c 'echo done > /data/out/status.txt'

What came back is bounded, checked before any of it lands, and identified by
content in the chain-signed audit log — the output-side mirror of the `--asset`
input identities, so a run reads inputs → signed plan → outputs.

## The surface, and why it is a disk and not a tar

The flush that landed before this made a writable disk image durable on every
guest, including arbitrary OCI images. That turned the tar-on-a-disk design
into the heavier option: it needed a pack step in `mvm-guest-agent` that runs
between workload exit and teardown, and a second tar codec fed by the guest.
The disk needs neither. The guest writes files into an ordinary ext4 mount;
after teardown the host reads the image in-process with `ext4-view`, the reader
`mvm-client`'s volume service already trusts with guest-written images. There
is no request to the guest at all.

The output disk is a fresh sparse image in a private scratch directory under
`~/.mvm/state/outputs/`, attached through the same disk-volume path as
`--mount HOST:/GUEST:SIZE:rw` — so the lock, the flush, and the host-fs share
grant are the existing ones. Nothing on the host is visible to the guest.

## What is enforced, where

`mvm_fs::output` owns the rules, in two passes so a refusal never leaves a
partial tree: the whole image is validated against every rule and both bounds
first, touching nothing; only then is it extracted, through directory handles
opened `O_NOFOLLOW` with every file created `O_EXCL`. A failure mid-extraction
removes what the collection created.

- Only regular files and directories. Symlinks, character and block devices,
  FIFOs, and sockets refuse. The inode decides the type; a directory entry that
  disagrees with its inode refuses rather than being believed.
- Names that are empty, `.`, `..`, not UTF-8, or contain `/` or NUL refuse;
  joined paths are checked again with the OCI unpacker's own escape rules,
  lifted into a shared `escaping_path_refusal`, plus depth (64) and length
  (4096 bytes) bounds.
- Byte and entry bounds are declared on the flag, signed into the plan, and
  read back *from the admitted plan* at collection. Exceeding either refuses the
  whole collection with a message naming the bound.
- The destination must be absent or empty; its parent is resolved at grant time
  and a parent that resolves elsewhere at collection refuses. The manifest
  sibling `HOST_DIR.manifest.json` must not exist.

## The record

`ExecutionPlan.outputs` carries each `OutputGrant` (guest path, resolved host
directory, `max_bytes`, `max_entries`); synthesis refuses a grant with no
writable disk share at its guest path. After collection `plan.outputs` records
`outcome=collected` with `manifest_sha256`, `entry_count`, `total_bytes`, and
`tree_sha256` — the digest `--asset` computes for that directory, so a later run
consuming these files names them by the same identity — or `outcome=refused`
with only the rule's tag. No guest-chosen path reaches the chain.

The manifest digest is SHA-256 over a domain tag
(`mvm.output-manifest.v1\0`), the entry count, and each entry in path-byte order
as a kind byte and length-prefixed fields. The pinned test vector was checked
against an independent implementation of that encoding.

## Not done

- A file hard-linked under two names inside the image is collected as two
  independent host files, each charged against the byte bound. `ext4-view`
  exposes no inode identity, so the link cannot be refused; the host never
  receives an alias. Recorded as an open item in the plan.
- `--output` is refused on persistent machines and `--entrypoint` runs, which
  have no foreground exit to collect at.
