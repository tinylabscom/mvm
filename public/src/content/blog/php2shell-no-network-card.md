---
title: "PHP2Shell gets a process. Not the keys."
description: "What an attacker can reach after exploiting PHP2Shell inside MVM, what stays outside PHP's access, and how to update an affected guest."
date: 2026-10-21T12:00:00-07:00
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

Suppose the exploit works and the attacker takes over the worker. Here's what they can do in the MVM configuration described here:

| Area | What compromised PHP can do inside MVM | How MVM limits the damage |
|---|---|---|
| **Process memory** | Read non-sensitive state held by PHP | MVM handles sensitive-value substitution at ingress and egress, outside PHP. The worker cannot read the secrets, session material, or customer data handled there. |
| **Responses** | Return false results or change application behavior | MVM does not guarantee correct application responses after PHP is compromised. The PHP update is still required. |
| **Availability** | Crash workers or consume the guest's assigned memory | MVM confines memory allocation to the guest's limit. PHP cannot allocate beyond that limit to exhaust host memory. |
| **Files** | Read files available to the PHP process | MVM keeps the sealed root read-only. The limited writable mounts are designated non-root paths outside PHP's access. |
| **Network and services** | Use destinations and host services allowed by the signed plan | MVM's host-owned endpoint enforces the plan. Compromising PHP does not grant access to undeclared destinations or services. |

You still have a broken service: it can return bad results or stop responding. That's reason enough to replace the affected guest.

Taking over PHP does not give the attacker additional permissions. MVM enforces the workload's network, filesystem, and resource limits outside the PHP process, so compromising the worker does not let an attacker change those limits:

**Network access stays on the allowlist.** Opening a socket inside the guest doesn't create an Internet connection. The host endpoint checks the destination and protocol before opening an external connection. The attacker can try to use an allowed destination, which is why the allowlist should be narrow, but can't add a new one.

**Host files aren't there to browse.** The guest sees only the shares included in the plan, read-only by default. In this configuration, only a small set of designated non-root paths can be mounted writable. Those paths are outside PHP's access, even after the worker is compromised.

**Sensitive values stay outside PHP.** Substitution happens at ingress and egress, not in the worker. The secrets, session material, and customer data handled there aren't available for PHP to read. For managed credentials, the host inserts the credential for the approved destination at the egress gate. It never enters PHP's memory.

**Memory exhaustion stops at the guest's allocation.** The worker can use up the guest's memory and take down its own workload. It can't allocate beyond that limit to exhaust host memory.

**The root filesystem stays read-only.** Block-backed production images are also verified with dm-verity. The attacker can change process memory while the VM is running, but can't use that access to rewrite the verified root for the next boot. The designated writable mounts remain outside PHP's access.

**Host services still check permissions.** A vsock connection doesn't bypass the plan. Host-side brokers accept only the services approved for that workload.

## Why the PHP update is still mandatory

These restrictions don't repair PHP's memory-corruption bugs. They give you a smaller incident to recover from while you replace the vulnerable runtime.

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

### With MVM: one operator action

> **Relaunch with a published and signed update that includes the fixed PHP release.**

In this MVM configuration, substitution already keeps sensitive values outside PHP, and the access limits remain enforced after compromise. The fixed PHP release comes with the new image. You replace the guest rather than update packages or try to clean up the compromised instance in place.

---

## Primary sources

- [PHP Foundation disclosure and fixed releases](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/)
- [PHP 8.5.12 release announcement](https://www.php.net/releases/8_5_12.php)
- [Wiz technical analysis](https://www.wiz.io/blog/php2shell-php-rce)
- [Cloudflare mitigation analysis](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/)
- [OpenAI coordinated-disclosure report](https://openai.com/index/coordinated-disclosure-of-critical-vulnerabilities/)
