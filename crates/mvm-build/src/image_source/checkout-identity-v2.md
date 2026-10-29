# Checkout identity, version 2

This is the normative binary fingerprint contract shared by the Rust checkout
observer and the local-manifest emitter. Checkout identity version 2 is
independent of the image-set schema: new Linux-only sets use schema 3 and
base-image contract 1. Historical signed schema 2 sets remain unchanged.

## Wire compatibility

Clean is exactly `{"state":"clean"}`. It has no fingerprint or version, including
no null fields. Historical clean identities remain readable.

Dirty is `{"state":"dirty","fingerprint_version":2,"fingerprint":"<sha256>"}`.
The digest is lowercase hexadecimal SHA-256 of the binary stream below.
Missing or unsupported dirty versions require rebuilding the local image set.
They must never be compared as version-2 digests, even when the recorded mvm
checkout is only provenance. Version 1 was a porcelain/diff-based digest and is
not reproducible by the new algorithm.

## Binary stream

Integers are unsigned little-endian. `field(bytes)` is `u64(length)` followed by
the exact bytes. Paths are repository-relative, slash-separated, sorted by
unsigned bytewise lexicographic order. On Unix they are filesystem bytes, never
decoded, replacement-decoded, normalized as Unicode, or quoted.

1. The 16 bytes `mvm-checkout-v2\0` (the final byte is NUL).
2. HEAD's raw 20-byte SHA-1 commit ID.
3. `I` (one byte), `u64(index entry count)`, then each index record:
   `field(path)`, `u32(mode)`, `u32(stage)`, `u32(flags)`, raw 20-byte object ID.
   Entries at the same path are sorted by stage (0, 1, 2, 3).
   Flags are assume-valid=1, intent-to-add=2, skip-worktree=4, ORed together.
   Index stat-cache metadata and all other implementation/cache flags are absent.
4. `W`, `u64(distinct index path count)`, then each working record:
   `field(path)`, `u32(mode)`, `field(body)`.
5. `U`, `u64(non-ignored untracked leaf count)`, then each untracked record,
   with the same layout as W.

Modes are Git modes: regular 100644, executable 100755, symlink 120000,
gitlink 160000, directory obstruction 040000 (all octal).
A missing tracked path has mode 0 and an empty body. Files have their **raw**
working bytes, links their raw target bytes, directory obstructions an empty
body. Empty untracked directories are absent. `.git` administrative paths are
never U inputs, including those below nested directories.

Gitlink bodies are the raw 20-byte submodule HEAD and a byte: 0 for clean,
1 for dirty followed by its raw 32-byte version-2 fingerprint. Uninitialized
absent/empty gitlinks use their index ID and byte 0. An initialized but
inaccessible, malformed or non-repository submodule is an error, never an
uninitialized or clean substitute. Cycles and nesting beyond 64 repositories
are errors.

On Unix execute mode is determined by the owner's execute permission bit, as
Git's regular/executable mode normalization does. On platforms
without Unix execute bits the working regular-file mode is 100644. For
cleanliness comparison only, `core.filemode=false` retains the index's regular
mode and `core.symlinks=false` accepts a regular-file symlink placeholder.
The dirty fingerprint retains the observed mode. Tracked name matching respects
`core.ignorecase`; case-folded tracked names are not duplicated in U.

## Repository observation

HEAD must name an existing commit. Object and index parsing, linked-worktree
resolution, supported Git config/includes and rule matching are in-process. Ambient
repository-location, alternate-object and index redirects do not choose the
repository. HEAD versus index, all conflict stages, intent-to-add, tracked
working bytes/modes, nonignored untracked leaves and recursively observed
gitlinks determine dirty state. Assume-valid and skip-worktree do not hide
build-visible tracked edits.

Ignore rules include directory-local `.gitignore`, the common repository's
`info/exclude`, and configured/global excludes. Tracked paths are not ignored.
Attributes use working files then index fallback, global rules, and common
`info/attributes`. Built-in text/auto/eol/crlf and ident normalization is
in-process and is used **only** for cleanliness comparison. CRLF auto detection
uses Git's printable/nonprintable/NUL/lone-CR statistics and index CRLF guard.
Raw working bytes still distinguish two dirty builds.

No observer enters a status/filter pipeline, hook, fsmonitor command, credential
helper, diff helper, transport, Git executable or interpreter subprocess.
Active external filters and working-tree-encoding are explicitly refused;
ignoring an unsupported transform is not a successful observation.

The `attributes` dependency feature enables `gix-command`; that capability is
not globally disabled. Production enters only isolated repository/data APIs:
open permissions disable Git-binary config discovery and config includes,
attributes assemble explicit global files rather than installation discovery,
and excludes resolve the already-normalized config paths as data. In gix
0.87.1 the interpolation prefix used by open/excludes is the current
executable's parent, not `git --exec-path`. No filter pipeline is constructed.
The executable-trap regression witnesses rule observation and filter refusal
without invoking an available hostile `git`.

Sparse directory indexes expand through the repository object store. Missing
skip-worktree files are intentional omissions, not edits; present files are
still read and compared. Both observers use bounded EWAH/link adapters, which
verify main/shared-index checksums and hydrate replacements and deletions before
observation. Rust uses pure-Rust gix for HEAD/objects and attribute/ignore
parsing. Git configuration grammar is parsed through gix-config's event API;
the bounded include adapter retains actual gitdir/onbranch context, ordering,
duplicates and valueless versus empty values. The repository is opened with
isolated permissions and receives only the observer's explicitly constructed
config. HEAD/commit/tree/blob lookups use that same owned handle; they do not
trigger a second default home-config loader.
Attribute/exclude paths are resolved from the current declared HOME/XDG and
installed in the owned gix config. Missing optional home files or
directories mean absent rules, not errors or a lookup in a cached/real home.
For both `core.attributesFile` and `core.excludesFile`, the shared resource-path
contract is:

- Absolute paths are used unchanged.
- Relative paths are rooted in the actual observed worktree, not process cwd.
- `~/` expands using the current declared `HOME`, or `USERPROFILE` only when
  `HOME` is absent. With neither declared, an explicit `~/` resource is refused.
- `%(prefix)` refuses on POSIX: no installation prefix is proven. Windows
  retains data-only proven-prefix expansion, without PATH executable-layout
  heuristics. This resource-path support does not enable `%(prefix)` includes.
- An unspecified resource uses nonempty current `XDG_CONFIG_HOME`, otherwise
  declared home plus `.config`, followed by `git/attributes` or `git/ignore`.
  A relative derived path is likewise rooted in the worktree. With neither
  home nor XDG declared, the resource is absent (represented by the null device).

No resource-path step discovers a user's real home through pwd/native cached
home lookup. The bounded config include adapter also expands `~/` paths and
home-based gitdir conditions using the current declared home.
Non-UTF-8 file paths are supported on Unix.
Dulwich's UTF-8 decoding of an administrative `.git` pointer is a separate
linked-metadata limitation.

### Normative source policy

Version 2 defaults internally to NoSystem config and attributes. Normal
commands need no environment flags. Repository config, declared HOME/XDG and
explicit global config remain contributing sources. Unset system controls
exclude system sources. Explicit true `GIT_CONFIG_NOSYSTEM` excludes system
config even with `GIT_CONFIG_SYSTEM`; otherwise the latter opts in exactly its
accessible file. That file does not opt in system attributes or prove an
installation prefix. Explicit false requesting implicit system discovery must
refuse when its path cannot be proven. `GIT_ATTR_NOSYSTEM=true` excludes system
attributes; false refuses unproven discovery. A proven Windows installation
can opt into its exact `etc/gitattributes`, independently of system config.
No global environment is mutated.
The resolved policy is internal, not an extra image-manifest field: these are
fixed V2 observation rules for both historical schema 2 and schema 3 identities.

Bool validation precedes clean returns for filemode, ignorecase, symlinks,
worktreeconfig and bare, plus autocrlf (whose `input` value is also accepted).
Valueless means true and explicit empty means false. Keywords yes/on/true and
no/off/false are case-insensitive; base-zero signed integers and k/m/g binary
units must fit a signed 32-bit int. Garbage refuses. Unsupported environment
injection through `GIT_CONFIG_COUNT` or `GIT_CONFIG_PARAMETERS`, unknown
includeIf forms, and symlink/nonregular per-directory rules refuse.

Encountered `hasconfig` conditional includes and `%(prefix)` include paths
are explicitly refused, including in contributing included files; silently
dropping them would change which rules contribute. Ordinary gitdir, gitdir/i and
onbranch contextual includes retain config-level precedence.

git2 and libgit2-sys are no longer dependencies. Fixture object lookups use gix
and linked-worktree metadata is written directly. Native `git config` is
retained as a tests-only differential oracle for include conditions, not a
fixture producer or runtime dependency. Repository creation, staging and commits
use deterministic in-process object, index and reference encoding. The combined
image-source suite covers these fixtures and the policy above; schema 3 paired
producer validation and platform acceptance remain separate requirements.

## Shared vectors and provenance

Expected hashes were calculated from hand-encoded literal binary streams with
`printf`/`xxd` and `shasum -a 256`, independently of both observer encoders.
No Git repository or subprocess-generated status/diff fixture was involved.
Both languages assert the same values:

| Input | SHA-256 |
| --- | --- |
| HEAD=20 zero bytes, I/W/U empty | `f05485947d595bce2f26829620e3dfcdd28c7248b6dc0d20681c1ad2699b1ecb` |
| Same HEAD, I/W empty, U=(path ff, mode100644, body00ff0a) | `06e6284c46206320bd0679940642175026ef97888a63afd2e166c5119ad88787` |
| HEAD=11 repeated20; I=(ff,100755,stage2,flags7,oid22 repeated20); W=(ff,0,empty); U=(6c,120000,ff0a) | `7ff6f04e29602de8984dde4663b9b41edd4b441d37c66e74d0c477d0b175171d` |
| HEAD=11 repeated20; I=(73,160000,stage0,flags0,oid22 repeated20); W=(73,160000,oid22 repeated20 + 00); U empty | `e535f6bf8dc4488cf36988106591011f5fdcbe778163423d006fc3bfe62c1cd8` |

The real fixture in both languages creates a repository in-process,
commits `a.txt`=`tracked\n`, then changes it to `tracked\nchanged\n`,
adds `u.txt`=`untracked\n` and a symlink `link`→`a.txt`. Both author and committer
are `mvm-test <mvm-test@example.invalid>`, timestamp 1700000000 UTC, message
`fixture\n`, no parents or extra headers:

- blob: `93a9e06d23ffb27541048940052c7a076c7a195a`
- tree: `64acc3933bc4e58fd5159670145fe39f57cd169c`
- commit: `d40e7ed3d340d03c7ad6910387c60943c0ff3d0d`
- V2: `62287e21e3b30dc2978c2e7e05f65e9770e6a641048161493425b0799c734bae`

Rust `tests/git_identity.rs` and Python `Fingerprint` cover the four encoding
vectors and real repositories for index edits, conflicts, stat cache, hidden
flags, ignored paths, modes, raw paths, links, deletion, linked worktrees,
external-transform refusal, builtin normalization and malformed submodules.
The old manifest digest survives only in the legacy-dirty refusal test.
