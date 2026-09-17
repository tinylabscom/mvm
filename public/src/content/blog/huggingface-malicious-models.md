---
title: "No CVE, no patch, no warning: the malicious models on Hugging Face"
description: "The ~100 backdoored models JFrog found on Hugging Face weren't a library bug — they were the model format doing what it was designed to do: run code the moment you load it. Here's the attack, and how running an untrusted model inside MVM turns that reverse shell into a logged non-event inside a disposable box."
date: 2026-09-16
tags:
  - security
  - supply-chain
  - machine-learning
  - containment
  - honest-posture
heroImage: /blog/huggingface-malicious-models.svg
heroAlt: "A diagram showing a downloaded .pt/.bin model file whose bytes are a pickle, loaded with torch.load, triggering a __reduce__ opcode that runs attacker code in the host process as a reverse shell — before the first weight is read."
---

## A model is not a document

When you download a PDF, nothing runs. When you download a `.pt` or `.bin`
PyTorch model, something can — and that is not a vulnerability in any one
library, it is the file format working as designed.

Most PyTorch checkpoints are Python **pickles**. Pickle is not a data format in
the sense JSON is; it is a little stack program that the `pickle` module
*executes* to rebuild an object. One of its opcodes, driven by an object's
`__reduce__` method, says "call this callable with these arguments." Point that
callable at `os.system` and the argument at a reverse-shell one-liner, and the
payload runs the instant you call `torch.load` — before the first weight is
read, before inference, before anything you would recognize as "using the
model."

In early 2024, [JFrog scanned models on the Hugging Face Hub and found roughly
one hundred](https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor/)
that did exactly this: silent backdoors that hand the attacker a shell on
whatever machine loads them
([The Hacker News](https://thehackernews.com/2024/03/over-100-malicious-aiml-models-found-on.html),
[Dark Reading](https://www.darkreading.com/application-security/hugging-face-ai-platform-100-malicious-code-execution-models)
covered the finding). It was never assigned a CVE, and that is the first honest
thing to say about it — there is no single upstream line to patch. The Hub is a
package registry for objects that execute on load, and the malicious models were
valid files. This is a supply-chain problem, not a memory-safety one.

## The trust boundary is the download button

The thing that makes this dangerous is how ordinary the triggering action is. A
data scientist evaluating a new checkpoint types the same two lines they type
every day:

```python
model = AutoModel.from_pretrained("some-org/some-model")
```

There is no `eval()` in *their* code to audit, no obviously dangerous call. The
danger is upstream, in bytes they trusted because the Hub served them. And the
process that runs the payload is a developer laptop or a training box — which
tends to hold exactly what an attacker wants: cloud credentials, SSH keys,
source code, access to the internal network.

Hugging Face's own mitigations — pickle scanning, marking files "unsafe,"
promoting the [`safetensors`](https://github.com/huggingface/safetensors)
format — are real and have helped. But scanning pickles is an arms race (the
tools that do it, like [PickleScan](https://github.com/mmaitre314/picklescan),
have had their own
[bypass CVEs](https://nvd.nist.gov/vuln/detail/CVE-2025-10155)), and marking a
file "unsafe" doesn't stop anyone from loading it. The durable fix is to stop
loading formats that can execute at all.

## What MVM changes: the shell opens into an empty room

Picture the payload landing where it was meant to: a developer laptop or a
training host, holding cloud credentials, SSH keys, source, and a route into the
internal network. The pickle fires, the reverse shell opens, and the attacker
inherits all of it. That is the incident JFrog described.

Now run the exact same model inside a sealed MVM workload. The pickle still
fires — MVM doesn't stop pickle from doing what pickle does — but the shell it
opens looks out on an empty room. Every move the payload was written to make is
already walled off before it starts:

- **It reaches for the network to phone home — and there is no network.** The
  guest has no network device at all, only a single channel to a host-side
  egress gate that is deny-by-default. The reverse shell's connection is refused
  unless an operator admitted that destination by policy, and the attempt is
  logged. A backdoor that can't call out is a backdoor to nowhere.
- **It reaches for credentials — and there are none to take.** Raw secrets never
  enter the guest. Full code execution finds no key, no token, nothing to steal
  even if it had somewhere to send it.
- **It reaches for persistence — and the box is disposable.** The rootfs is
  immutable and cryptographically verified; the next run is an identical clean
  box, and the backdoor doesn't survive it.
- **It tries to stay quiet — and it's already on the record.** Admission and
  every policy decision land in a signed audit log the operator reads.

None of these are reactions to *this* attack. They're the standing posture MVM
enforces on every workload, each pinned by a named test or CI gate in the
[claims ledger](/security/ci-claims/). The malicious model executes into the
same sealed box a benign one would — and finds nothing there worth having. A
breach becomes a logged non-event inside a disposable boundary.

That is the whole argument for treating an untrusted model the way you'd treat
untrusted code: not "scan it and hope," but "run it somewhere it can't hurt
you." The people JFrog's finding hit were loading models straight onto their
laptops, outside any sandbox — the exact habit this incident should end. MVM is
the boundary you run them in.

## Closing the gap: don't just contain it, refuse it

Containment is the backstop that holds today. The stronger move is to never load
an executable model in the first place — and that's where MVM's model runtime is
headed. By design it refuses pickle outright, establishes a file's true format
from its bytes rather than its extension (a pickle renamed `.safetensors` is
refused), and treats the model as inert data behind a runtime that speaks only
execution-free formats like `safetensors`. A model that can't execute on load
can't backdoor you on load.

Both are still ahead of us, and worth naming precisely: the execution-free
loader is **designed but not yet built**, and mvm-scout — MVM's static analyzer,
the tool that flags dangerous code before a workload runs — reads source, not
model artifacts, so the pickle-opcode analyzer that would catch this is
**roadmap, not shipped**. Together they'd turn "contained if you run it inside
MVM" into "refused before it runs at all." Until then, containment carries it.

## The bottom line

You can't patch this the way you patch a CVE — there's no upstream line to fix,
because the model was a valid file doing what its format allows. What you *can*
do is stop handing an untrusted artifact the run of a machine that matters. Run
it inside MVM and the worst case shrinks from "the attacker owns your laptop and
your cloud keys" to "a sealed, disposable box logged an attempt to reach a
network it doesn't have." Refusing the format and scanning the artifact will make
that tighter still. Containment makes it true today.

## Status behind this post

Unlike our CVE teardowns, this post describes no experiment we ran against a
specific artifact — so its table is a capability ledger, not an evidence table.
It records what is shipped, what is designed, and what is not us.

| | |
|---|---|
| Threat | Malicious pickle models on the Hugging Face Hub (JFrog, 2024) |
| CVE | none — a supply-chain research disclosure, not a single patchable flaw |
| Root mechanism | Pickle `__reduce__` opcode executes on `torch.load` |
| mvm-scout coverage | none today — scout reads source, not model artifacts |
| Artifact scan mode | on roadmap, not shipped |
| Execution-free model loader | designed, implementation unscheduled |
| Runtime containment | shipped — applies only to models loaded inside an MVM workload |
| Containment demo against this threat | not run |

Nothing here certifies Hugging Face, MVM, or any scanner. The malicious-model
class fires wherever an execution-capable format is loaded without a boundary
around it — which is the exact condition this post argues to remove.
