import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";
import { Button } from "../ui/button";
import { GlowCard } from "./primitives/GlowCard";

// Copy below is deliberately narrower than plain-language marketing prose —
// it tracks the exact wording of the project's gated security-claims table,
// which is CI-enforced and authoritative over any summary (including this
// one). No numeric claim badge is shown: the destination docs pages predate
// this table's numbering, so a number here would resolve to nothing there.
//
// All four run as cards. An earlier revision showed two, which contradicted
// the prose beside it ("Four of mvm's CI-enforced security claims..."); the
// button still links out to the full ledger.
const FEATURED_CLAIMS: Array<{
  title: string;
  description: string;
  witnesses: string;
}> = [
  {
    title: "A tampered rootfs fails to boot",
    description:
      "On the block-and-ext4 backends, a dm-verity sidecar and a kernel-cmdline root hash mean a flipped data block panics the kernel before userspace ever runs.",
    witnesses: "ci:verified-boot-artifacts, fn:verify_and_resume_rejects_tampered_mem",
  },
  {
    title: "No untrusted workload reaches the network unless policy admits it",
    description:
      "Network policy defaults to deny-all. An unrestricted policy is opt-in only, and choosing it emits a warning rather than silently widening the default.",
    witnesses: "fn:policy_default_is_deny_all, fn:run_net_default_is_deny_all",
  },
  {
    title: "No raw secret value crosses the broker channel",
    description:
      "host.secrets.v1 returns destination-bound, time-bound signed credentials only. Raw secret bytes never leave the supervisor's address space.",
    witnesses:
      "fn:encode_secret_env_cmdline_round_trips_pairs_as_single_token, fn:substitute",
  },
  {
    title: "A production-safe run cannot invoke DevOnly guest-agent verbs",
    description:
      "The universal agent classifies every request and requires both the runtime profile and a signed VerbGrant before it will run a developer-only verb.",
    witnesses:
      "fn:prod_safe_grant_refuses_all_dev_only_requests, ci:guest-agent-runtime-boundary",
  },
];

export function Security() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    <Section rule space="tight">
      <div className="grid gap-10 lg:grid-cols-[minmax(0,0.85fr)_minmax(0,1.15fr)] lg:gap-16">
        {/* Left: statement + escape hatch to the rest. */}
        <Reveal>
          <Eyebrow>Security</Eyebrow>
          <h2 className="mb-4 lowercase font-display tracking-tight text-2xl font-semibold leading-tight text-title sm:text-3xl">
            trust the boundary
          </h2>
          <p className="mb-4 max-w-md text-base leading-relaxed text-body">
            The boundary above isn&rsquo;t a claim you have to take on faith.
            Four of mvm&rsquo;s CI-enforced security claims are backed by a
            named test or CI job. A malicious host, multi-tenant guests, and
            hardware-backed key attestation are explicitly out of scope.
          </p>
          <a href={`${base}security/claim-ledger/`}>
            <Button variant="outline">Read all claims</Button>
          </a>
        </Reveal>

        {/* Right: all four claims as compact cards — the prose above promises
            four, so rendering two made the section contradict itself. */}
        <div className="flex flex-col gap-6">
          {FEATURED_CLAIMS.map((c, i) => (
            <Reveal key={c.title} delay={i * 60 + 80}>
              {/* min-w-0 on the card, not just the witness line: as a flex
                  item it defaults to min-width:auto and so refuses to shrink
                  below its widest unbreakable child. Witness identifiers are
                  long single tokens (fn:encode_secret_env_cmdline_...), which
                  pushed this card past the viewport at 390px. break-all
                  rather than break-words because these are mono identifiers —
                  breaking mid-token is fine and wrapping at all is not
                  otherwise possible. */}
              <GlowCard accent={3} className="min-w-0 p-6 sm:p-7">
                <h3 className="mb-2 text-base font-semibold leading-snug text-title">
                  {c.title}
                </h3>
                <p className="mb-3 text-sm leading-relaxed text-body">{c.description}</p>
                <p className="min-w-0 font-mono text-[11px] break-all text-label/70">
                  {c.witnesses}
                </p>
              </GlowCard>
            </Reveal>
          ))}
        </div>
      </div>
    </Section>
  );
}
