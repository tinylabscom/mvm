import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { GlowCard } from "./primitives/GlowCard";
import { Reveal } from "./primitives/Reveal";

// Copy below is deliberately narrower than plain-language marketing prose —
// it tracks the exact wording of the claims table in
// specs/adrs/001-microvm-security-posture.md, which is CI-gated and
// authoritative over any summary (including this one).
const CLAIMS: Array<{
  n: number;
  title: string;
  description: string;
  witnesses: string;
  docHref: string;
  accent: 1 | 2 | 3;
}> = [
  {
    n: 3,
    title: "A tampered rootfs fails to boot",
    description:
      "On the verified-boot backends, a dm-verity sidecar and a kernel-cmdline root hash mean a flipped data block panics the kernel before userspace ever runs.",
    witnesses: "ci:verified-boot-artifacts, fn:verify_and_resume_rejects_tampered_mem",
    docHref: "security/verified-boot/",
    accent: 1,
  },
  {
    n: 10,
    title: "No untrusted workload reaches the network unless policy admits it",
    description:
      "Network policy defaults to deny-all. An unrestricted policy is opt-in only, and choosing it emits a warning rather than silently widening the default.",
    witnesses: "fn:policy_default_is_deny_all, fn:run_net_default_is_deny_all",
    docHref: "security/matryoshka/",
    accent: 2,
  },
  {
    n: 13,
    title: "No raw secret value crosses the broker channel",
    description:
      "host.secrets.v1 returns destination-bound, time-bound signed credentials only. Raw secret bytes never leave the supervisor's address space.",
    witnesses: "fn:encode_secret_env_cmdline_round_trips_pairs_as_single_token, fn:substitute",
    docHref: "security/threat-model/",
    accent: 3,
  },
  {
    n: 15,
    title: "A sealed production microVM has no shell, no DevOnly verbs, no PTY",
    description:
      "The only console path is a signed-grant-gated PTY served by the guest agent, refused outright on a sealed image before any request reaches it.",
    witnesses: "fn:console_refused_on_sealed_image, ci:guest-agent-runtime-boundary",
    docHref: "security/ci-claims/",
    accent: 1,
  },
];

export function Security() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    <Section rule>
      <Eyebrow n="06">Security</Eyebrow>
      <h2 className="mb-4 font-display text-3xl font-bold text-title sm:text-4xl">
        Claims backed by tests, not adjectives
      </h2>
      <p className="mb-4 max-w-2xl text-lg leading-relaxed text-body">
        These are four of the CI-enforced security claims in mvm's threat
        model, each with a named test or CI job as its witness. A malicious
        host, multi-tenant guests, and hardware-backed key attestation are
        explicitly out of scope.
      </p>
      <p className="mb-12 max-w-2xl text-sm text-label">
        See the full{" "}
        <a
          href={`${base}security/claim-ledger/`}
          className="text-accent underline underline-offset-2 hover:text-accent/80"
        >
          claim ledger
        </a>{" "}
        for every claim, its witnesses, and its status.
      </p>

      <div className="grid gap-5 sm:grid-cols-2">
        {CLAIMS.map((c, i) => (
          <Reveal key={c.n} delay={i * 80}>
            <GlowCard accent={c.accent}>
              <div className="mb-3 flex items-center gap-2">
                <span className="rounded border border-accent/30 bg-accent/10 px-2 py-0.5 font-mono text-[11px] text-accent">
                  claim {c.n}
                </span>
              </div>
              <h3 className="mb-2 text-lg font-semibold leading-snug tracking-tight text-title">
                {c.title}
              </h3>
              <p className="mb-3 text-sm leading-relaxed text-body">
                {c.description}
              </p>
              <p className="mb-3 font-mono text-[11px] text-label">
                {c.witnesses}
              </p>
              <a
                href={`${base}${c.docHref}`}
                className="text-sm text-accent underline underline-offset-2 hover:text-accent/80"
              >
                Read more
              </a>
            </GlowCard>
          </Reveal>
        ))}
      </div>
    </Section>
  );
}
