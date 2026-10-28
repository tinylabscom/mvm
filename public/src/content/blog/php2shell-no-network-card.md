---
title: "PHP2Shell gets a process. Patching still matters."
description: "What an attacker can reach after exploiting PHP2Shell inside MVM, which protections depend on the workload configuration, and how to update an affected guest."
date: 2026-10-21T12:00:00-07:00
shareHook: "PHP2Shell can own the process. Does that mean it gets the network too? Where microVM containment helps, and why patching still matters."
tags:
  - security
  - php2shell
  - microvm
  - containment
  - defense-in-depth
heroImage: /blog/php2shell-no-network-card.svg
heroAlt: "A hostile HTTP request crosses a declared host-owned ingress into a compromised PHP process inside an MVM microVM, while the no-NIC boundary and host-owned FlowMux gate prevent undeclared network access."
---

PHP2Shell lets an attacker take over a PHP worker without logging in. Running that worker inside MVM doesn't fix the PHP bug, but it limits what the attacker can reach once they're in.

The two flaws, [CVE-2026-109618 and CVE-2026-109619](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/), are in PHP's memory management and error handling—not in WordPress, Drupal, Joomla, or an application plugin. An unauthenticated request can corrupt PHP's internal state, disclose memory from a worker, and, under the right conditions, execute attacker-controlled code. Wiz demonstrated pre-authentication remote code execution against current application images. The PHP project released 8.2.35, 8.3.36, 8.4.27, and 8.5.12 to fix it.

**You'll need the fixed PHP release.** For an MVM deployment, that means relaunching with a published, signed update that includes it.

MVM limits what a compromised worker can reach. Guests have no network device. Ingress and egress pass through FlowMux, an authenticated vsock protocol, and a host-owned endpoint that enforces a signed plan. The root filesystem is read-only and, on the block-backed production path, protected by dm-verity.

## Published PHP services still need the patch

A guest without a network card can still receive requests if you publish a service through MVM. Those requests can include an exploit.

When you publish a service, the host listens for connections. The signed `ExecutionPlan` maps that listener to a specific loopback address and port inside the guest. FlowMux carries the traffic over vsock. The guest doesn't need a NIC, route table, TAP device, or bridge.

If you point that mapping at vulnerable PHP, an exploit request can reach it too. One of the disclosed paths can trigger before application code runs under Apache `mod_php`, so fixing a CMS or sanitizing an application route isn't enough.

Without declared ingress, there's no inbound route through MVM for that request. Publishing the service opens that route; it doesn't give the guest general network access.

## What successful RCE gets inside MVM

Suppose the exploit works and the attacker takes over the worker. The intended configuration here keeps managed credentials on the host's substitution path and restricts writable mounts to designated non-root paths that PHP is not permitted to access. Those are configuration requirements, not blanket guarantees for every MVM workload; a non-root path alone does not establish isolation.

> **Evidence boundary.** This is an architecture-backed scope analysis, not a report of a PHP2Shell experiment. The [security claim ledger](/security/ci-claims/) and [NIC-less networking guide](/guides/networking/) describe the existing boundaries. [Issue #4603](https://github.com/tinylabscom/mvm/issues/4603) remains open for a representative PHP fixture and artifact-, plan-, and backend-bound containment evidence, including secret-memory and mount-access witnesses. This post does not establish that those experiments have run or that the intended configuration has been empirically proved.

| Area | What compromised PHP can do inside MVM | How MVM limits the damage |
|---|---|---|
| **Process memory** | Read or corrupt whatever PHP holds, including sensitive data if present | Host-side substitution is intended to keep managed raw credentials out of the worker; it does not protect arbitrary secrets, session material, or customer data already in PHP. |
| **Responses** | Return false results or change application behavior | MVM does not guarantee correct application responses after PHP is compromised. The PHP update is still required. |
| **Availability** | Crash workers or consume the guest's assigned memory | The guest's allocation bounds worker memory use, not every source of host resource pressure. |
| **Files** | Read or modify files available to the PHP process with those permissions | MVM keeps the sealed root read-only. Keeping writable mounts outside PHP's access requires the specified access restrictions and separate verification. |
| **Network and services** | Use destinations and host services allowed by the signed plan | MVM's host-owned endpoint enforces the plan. Compromising PHP does not grant access to undeclared destinations or services. |

You still have a broken service: it can disclose data it holds, return bad results, or stop responding. That's reason enough to replace the affected guest.

The architectural boundary is intended to keep process compromise from widening the workload's admitted authority. Under the specified configuration, the limits are:

**Network access stays on the allowlist.** Opening a socket inside the guest doesn't create an Internet connection. The host endpoint checks the destination and protocol before opening an external connection. The attacker can try to use an allowed destination, which is why the allowlist should be narrow, but can't add a new one.

**Host files aren't there to browse.** The guest sees only the shares included in the plan, read-only by default. The intended configuration restricts writable mounts to a small set of designated non-root paths and denies PHP access to them. If a workload instead grants PHP access to a writable share, compromised PHP can modify it; a persistent share can retain those changes.

**Host-substituted credentials stay outside PHP.** On the managed substitution path, the guest receives a reference value and the host inserts the destination-bound credential at the egress gate. That is not a claim that all sensitive values are automatically removed at ingress or egress. Secrets manually placed in environment variables, files, mounts, databases, or PHP memory remain exposed to whatever access the compromised worker has.

**Memory exhaustion can still stop the workload.** The worker can use up the guest's memory and take down its own workload. A bounded guest allocation is not, by itself, proof against host-wide resource exhaustion.

**The root filesystem stays read-only.** Block-backed production images are also verified with dm-verity. The attacker can change process memory while the VM is running, but can't use that access to rewrite the verified root for the next boot. This does not make writable application data immutable or prove that PHP cannot reach a particular mount.

**Host services still check permissions.** A vsock connection doesn't bypass the plan. Host-side brokers accept only the services approved for that workload.

## Why the PHP update is still mandatory

These restrictions don't repair PHP's memory-corruption bugs. They are intended to bound the incident while you replace the vulnerable runtime, not eliminate application-data exposure or recovery work.

| Protection | Helps with | Still needs |
|---|---|---|
| **PHP update** | Fixes the disclosed memory-corruption bugs | Isolation against future exploits |
| **No NIC + FlowMux** | Blocks undeclared network access | A patched runtime for incoming HTTP |
| **Read-only, verified root** | Prevents persistent changes to the sealed root | Protection against live process compromise |
| **Signed service bindings** | Restricts access to approved services | Narrow permissions for each service |
| **WAF / ingress inspection** | Blocks some known exploit requests | A PHP update; filters can miss variants |

[Cloudflare’s PHP2Shell mitigation](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/) needed signals from both the request and the origin response, rather than a request-only signature. Attackers also began changing payloads to get around defenses after disclosure. Cloudflare still [tells customers to patch](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/).

### Without MVM: five remediation steps

1. Update PHP.
2. Rebuild the deployment artifact.
3. Review network access and writable paths.
4. Rotate or invalidate potentially exposed secrets and sessions.
5. Replace affected instances.

### With MVM: one operator action to replace the runtime

> **Relaunch with a published and signed update that includes the fixed PHP release.**

In the intended configuration, managed credentials stay host-side and access limits bound the workload's authority. The fixed PHP release comes with the new image. You replace the guest rather than update packages or try to clean up the compromised instance in place. This single runtime-replacement action does not replace incident recovery: review admitted capabilities and writable data, and rotate or invalidate secrets and sessions if they may have been exposed to PHP.

---

## Primary sources

- [PHP Foundation disclosure and fixed releases](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/)
- [PHP 8.5.12 release announcement](https://www.php.net/releases/8_5_12.php)
- [Wiz technical analysis](https://www.wiz.io/blog/php2shell-php-rce)
- [Cloudflare mitigation analysis](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/)
- [OpenAI coordinated-disclosure report](https://openai.com/index/coordinated-disclosure-of-critical-vulnerabilities/)
