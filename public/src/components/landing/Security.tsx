import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";

// Copy below is deliberately narrower than plain-language marketing prose —
// it tracks the exact wording of the project's gated security-claims table,
// which is CI-enforced and authoritative over any summary (including this
// one). No numeric claim badge is shown: the destination docs pages predate
// this table's numbering, so a number here would resolve to nothing there.
const CLAIMS: Array<{
  title: string;
  description: string;
  witnesses: string;
  docHref: string;
  accent: 1 | 2 | 3;
}> = [
  {
    title: "A tampered rootfs fails to boot",
    description:
      "On the block-and-ext4 backends, a dm-verity sidecar and a kernel-cmdline root hash mean a flipped data block panics the kernel before userspace ever runs.",
    witnesses: "ci:verified-boot-artifacts, fn:verify_and_resume_rejects_tampered_mem",
    docHref: "security/verified-boot/",
    accent: 1,
  },
  {
    title: "No untrusted workload reaches the network unless policy admits it",
    description:
      "Network policy defaults to deny-all. An unrestricted policy is opt-in only, and choosing it emits a warning rather than silently widening the default.",
    witnesses: "fn:policy_default_is_deny_all, fn:run_net_default_is_deny_all",
    docHref: "security/matryoshka/",
    accent: 2,
  },
  {
    title: "No raw secret value crosses the broker channel",
    description:
      "host.secrets.v1 returns destination-bound, time-bound signed credentials only. Raw secret bytes never leave the supervisor's address space.",
    witnesses: "fn:encode_secret_env_cmdline_round_trips_pairs_as_single_token, fn:substitute",
    docHref: "security/matryoshka/",
    accent: 3,
  },
  {
    title: "A production-safe run cannot invoke DevOnly guest-agent verbs",
    description:
      "The universal agent classifies every request and requires both the runtime profile and a signed VerbGrant before it will run a developer-only verb.",
    witnesses: "fn:prod_safe_grant_refuses_all_dev_only_requests, ci:guest-agent-runtime-boundary",
    docHref: "security/ci-claims/",
    accent: 1,
  },
];

export function Security() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    <Section rule space="tight">
      <Eyebrow>Security</Eyebrow>
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
        The identifiers below each claim name real tests and CI jobs, not
        links. mvm's docs follow a{" "}
        <a
          href={`${base}security/claim-ledger/`}
          className="text-accent underline underline-offset-2 hover:text-accent/80"
        >
          claim-safety ledger
        </a>{" "}
        that governs when a claim may be described as a guarantee.
      </p>

      <div className="max-w-2xl space-y-8">
        {CLAIMS.map((c, i) => (
          <Reveal key={c.title} delay={i * 60}>
            <div className="border-t border-edge/30 pt-6 first:border-t-0 first:pt-0">
              <h3 className="mb-2 text-lg font-semibold leading-snug tracking-tight text-title">
                {c.title}
              </h3>
              <p className="mb-2 text-sm leading-relaxed text-body">
                {c.description}
              </p>
              <p className="font-mono text-[11px] text-label">
                {c.witnesses}
                {" — "}
                <a
                  href={`${base}${c.docHref}`}
                  className="text-accent underline underline-offset-2 hover:text-accent/80"
                >
                  Read more
                </a>
              </p>
            </div>
          </Reveal>
        ))}
      </div>
    </Section>
  );
}
