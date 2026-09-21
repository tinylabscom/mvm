---
title: "No CVE, no patch, no warning: the malicious models on Hugging Face"
description: "The ~100 backdoored models JFrog found on Hugging Face weren't a library bug — they were the model format doing what it was designed to do: run code the moment you load it. Here's the attack, and how MVM scans the model and contains what runs."
date: 2026-09-16
tags:
  - security
  - supply-chain
  - machine-learning
  - static-analysis
  - containment
heroImage: /blog/huggingface-malicious-models.svg
heroAlt: "A diagram showing a downloaded .pt/.bin model file whose bytes are a pickle, loaded with torch.load, triggering a __reduce__ opcode that runs attacker code in the host process as a reverse shell — before the first weight is read."
---

## A model is not a document

When you download a PDF, nothing runs. When you download a `.pt` or `.bin` PyTorch model, something can — and that isn't a vulnerability in any one library, it's the file format working as designed.

Most PyTorch checkpoints are Python **pickles**. Pickle isn't a data format the way JSON is; it's a little stack program that the `pickle` module *executes* to rebuild an object. One of its opcodes, driven by an object's `__reduce__` method, says "call this callable with these arguments." Point that callable at `os.system` and the argument at a reverse-shell one-liner, and the payload runs the instant you call `torch.load` — before the first weight is read, before inference, before anything you'd recognize as "using the model."

In early 2024, [JFrog scanned models on the Hugging Face Hub and found roughly one hundred](https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor/) that did exactly this: silent backdoors that hand the attacker a shell on whatever machine loads them ([The Hacker News](https://thehackernews.com/2024/03/over-100-malicious-aiml-models-found-on.html) and [Dark Reading](https://www.darkreading.com/application-security/hugging-face-ai-platform-100-malicious-code-execution-models) covered the finding). It was never assigned a CVE, and that's the first thing to understand about it: there's no single upstream line to patch. The Hub is a package registry for objects that execute on load, and the malicious models were valid files. This is a supply-chain problem, not a memory-safety one.

## The trust boundary is the download button

What makes this dangerous is how ordinary the triggering action is. A data scientist evaluating a new checkpoint types the same two lines they type every day:

```python
model = AutoModel.from_pretrained("some-org/some-model")
```

There's no `eval()` in *their* code to audit, no obviously dangerous call. The danger is upstream, in bytes they trusted because the Hub served them. And the process that runs the payload is a developer laptop or a training box — which tends to hold exactly what an attacker wants: cloud credentials, SSH keys, source code, a route into the internal network.

Hugging Face has done real work here — it scans uploads for dangerous pickles, marks them "unsafe," and pushes people toward [`safetensors`](https://github.com/huggingface/safetensors), a format that can't carry code. That helps. But a warning label doesn't stop anyone from loading the file, and pickle scanners are in a cat-and-mouse game with people who craft pickles to slip past them — even [PickleScan](https://github.com/mmaitre314/picklescan) itself has had [bypasses](https://nvd.nist.gov/vuln/detail/CVE-2025-10155). The only durable fix is to not load a format that can execute in the first place.

## Caught before it loads

MVM treats a model the way it treats any other untrusted input: it scans it first. mvm-scout — MVM's static analyzer — reads the model artifact itself, the pickle's opcodes and not just source code, and flags a checkpoint that reaches for `os.system` or its kin. A backdoored model like the ones JFrog found is caught before `torch.load` ever touches it, which is the cheapest possible place to stop it: the payload never runs at all.

Scanning is the first line, not the only one. A scanner can be outrun by a new encoding or a trick nobody has a rule for yet — so MVM assumes a bad model will eventually get through, and makes sure that when one does, it lands on nothing.

## What MVM changes: the shell opens into an empty room

Picture a payload the scanner didn't catch, landing where it was meant to: a developer laptop or a training host, holding cloud credentials, SSH keys, source, and a route into the internal network. The pickle fires, the reverse shell opens, and the attacker inherits all of it. That's the incident JFrog described.

Now run that same model inside a sealed MVM workload. The pickle still fires — MVM doesn't stop pickle from doing what pickle does — but the shell it opens looks out on an empty room. Every move the payload was written to make is already walled off before it starts:

- **It reaches for the network to phone home — and there is no network.** The guest has no network device at all, only a single channel to a host-side egress gate that's deny-by-default. The reverse shell's connection is refused unless an operator admitted that destination by policy, and the attempt is logged. A backdoor that can't call out is a backdoor to nowhere.
- **It reaches for credentials — and there are none to take.** Raw secrets never enter the guest. Full code execution finds no key, no token, nothing to steal even if it had somewhere to send it.
- **It reaches for persistence — and the box is disposable.** The rootfs is immutable and cryptographically verified; the next run is an identical clean box, and the backdoor doesn't survive it.
- **It tries to stay quiet — and it's already on the record.** Admission and every policy decision land in a signed audit log the operator reads.

None of these are reactions to *this* attack. They're the standing posture MVM enforces on every workload, each pinned by a named test or CI gate in the [claims ledger](/security/ci-claims/). The malicious model executes into the same sealed box a benign one would — and finds nothing there worth having. A breach becomes a logged non-event inside a disposable boundary.

That's the whole argument for treating an untrusted model the way you'd treat untrusted code: scan it, and run it somewhere it can't hurt you if the scan misses. The people JFrog's finding hit did neither — they loaded models straight onto their laptops, outside any sandbox. That's the habit this incident should end. MVM is the boundary you run them in.

## The bottom line

You can't patch this the way you patch a CVE — there's no upstream line to fix, because the model was a valid file doing what its format allows. What you *can* do is stop handing an untrusted artifact the run of a machine that matters. Run it inside MVM: mvm-scout catches the backdoored model before it loads, and if a new one slips the scanner, containment shrinks the worst case from "the attacker owns your laptop and your cloud keys" to "a sealed, disposable box logged an attempt to reach a network it doesn't have."

## What MVM does about this threat

| | |
|---|---|
| Threat | Malicious pickle models on the Hugging Face Hub (JFrog, 2024) |
| CVE | none — a supply-chain research disclosure, not a single patchable flaw |
| Root mechanism | Pickle `__reduce__` opcode executes on `torch.load` |
| Detection | mvm-scout scans the model artifact and flags the pickle payload before load |
| Containment | sealed guest — no network device, no raw secrets, immutable verified rootfs, signed audit log |

The malicious-model class fires wherever an execution-capable format is loaded without a boundary around it — which is the exact condition MVM removes.
