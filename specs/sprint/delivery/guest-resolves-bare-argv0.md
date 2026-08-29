# The guest refused the command form its own README documents

`mvmctl run --mode live --profile dev ./script.py` is in the README and did not
work. The gate that found it recorded it as unproven; this is the fix.

## What #2887 said, and what was actually left

The issue was closed with a comment escalating a policy question: fs/proc are
DevOnly verbs, `default_agent_verbs` builds the grant from
`prod_safe_verb_names()`, `parse_agent_verb_override` rejects any non-ProdSafe
verb outright — so "a `machine run` launch can never carry a grant that
authorizes these verbs", and deciding otherwise was a claim-4 call that "wants an
owner rather than a drive-by".

That is no longer true, and it is worth saying plainly because it is why the
`@wip` tag outlived its reason. Against a live guest today:

```
$ mvmctl machine run -d --name devprof --image alpine --profile dev --ttl 300s
$ mvmctl machine fs read devprof /etc/hostname
localhost
$ mvmctl machine proc start devprof -- /bin/uname -s
ptok-9dd27e1b4d20e8fe16d2f620f9faa527
```

Both DevOnly verbs are authorized. The grant half was fixed by whatever landed
between that comment and now, and nothing updated the issue or the tag.

What was left is much smaller:

```
$ mvmctl machine proc start devprof -- uname -s
Error: Guest proc error (InvalidArgv): argv[0] "uname" must be an absolute path
```

## Three parts that did not agree

- **README**: `sb.commands.start(["python", "/app/main.py"])` and
  `sb.exec("uname", "-sr")` — bare command names.
- **SDK**: `_sandbox.py` forwards argv verbatim (`shell += ["--", *argv]`). No
  resolution, and none is possible host-side: the SDK does not know the guest's
  filesystem.
- **Guest**: `process_rpc.rs` refused any non-absolute `argv[0]`.

So the documented form could not run. The restriction carried no rationale
comment and arrived in a bulk crate-consolidation commit (#1720), not in a
change that was about it.

Meanwhile `exec` — the other half of the same documented pair — *did* accept a
bare name, because it builds a `WorkloadEnvironment` carrying the image's own
`PATH` and lets `Command` resolve through it
(`ad_hoc_exec_resolves_a_bare_command_from_the_image_path`). Two sibling verbs,
two different answers to the same input.

## The fix

`resolve_argv0` turns `argv[0]` into the absolute path that will be executed:

- an absolute path is taken as given — unchanged
- a **bare name** is looked up in the image's declared `PATH`, falling back to
  the FHS order when the image declares none
- a **relative path** (`./run`, `bin/tool`) is still refused: it resolves against
  a working directory the same request may be setting, so the two together decide
  the binary in a way neither states on its own

The property the old rule protected is unchanged: what reaches `execve` is still
an absolute path chosen in the parent before the fork. The only difference is
that a bare name now has a defined way to become one instead of being rejected.

**The request's own `PATH` is deliberately not consulted.** The caller supplies
that env, so honouring it would let the caller choose which binary a name
resolves to — which is the ambiguity refusing bare names avoided in the first
place. The image is not the caller, and the image is what `exec` already trusts.
A source-text test asserts the resolver reads no process environment.

## The test that had to change, and why that is not a weakened assertion

`build_command_rejects_relative_argv0` asserted a bare `echo` was refused. A bare
name is not a relative path, and refusing it is exactly what stopped the README's
example running. It is now
`build_command_rejects_a_relative_path_argv0` — `./echo` — plus
`build_command_resolves_a_bare_command_name`. The relative-path refusal it was
named for is strictly preserved; what it actually tested was the bug.

## Verified

```
$ mvmctl run --mode live --profile dev crates/mvm-conformance/fixtures/e2e/sandbox_script.py
EXIT=0
```

`files.write` is restored to the fixture. It was removed with a comment pointing
at #2887 and an instruction to restore it when fixed; it works, so it is back.
The scenario is retagged `@live` from `@wip`, and its manifest entry in
`readme_examples.toml` is promoted from an exemption to a real witness — the
README example is now proven rather than recorded as broken.

`scripts/e2e-launch-modes.sh` drops `pending` from its tolerated skips: nothing
in that lane is `@wip` any more, so a scenario parked mid-change would otherwise
reduce its coverage silently. Floor 21 → 22.

## The strict-skip gate paid for itself on its first real run

Turning the skip tally into a gate immediately caught something the tally had
been printing and nobody had acted on: `--mount shares a host directory the
workload can read` carries `@dir_share`, which needs `MVM_BDD_DIR_SHARE=1`, and
neither lane set it. That scenario is the witness for **both** of the README's
`--mount` examples, so two documented examples had a witness that did not
execute on a host perfectly capable of running it.

The message names the reason: libkrun and HVF serve virtio-fs directory shares;
Firecracker has no virtio-fs device and refuses `--mount` before boot. So both
lanes now set `MVM_BDD_DIR_SHARE=1` *and* tolerate `needs-dir-share` — a capable
backend runs the scenario, and only a genuinely incapable one skips it.
Tolerating the skip without opting in would have been the wrong half of that:
it silences the gate on exactly the host that could have proved the thing.
