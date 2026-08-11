import { Section } from "./primitives/Section";
import { Eyebrow } from "./primitives/Eyebrow";
import { Reveal } from "./primitives/Reveal";
import { Button } from "../ui/button";

// Copy below is deliberately narrower than plain-language marketing prose —
// it tracks the exact wording of the project's gated security-claims table,
// which is CI-enforced and authoritative over any summary (including this
// one). No numeric claim badge is shown: the destination docs pages predate
// this table's numbering, so a number here would resolve to nothing there.
//
// Four claims don't fit two cards, so only the two strongest run as cards —
// verified boot and default-deny egress, the two a reader can picture
// failing shut without reading the docs — and the button links to the rest.
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
          <h2 className="mb-4 lowercase font-display text-2xl font-bold leading-tight text-title sm:text-3xl">
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

        {/* Right: the two strongest claims as compact cards. */}
        <div className="flex flex-col gap-6">
          {FEATURED_CLAIMS.map((c, i) => (
            <Reveal key={c.title} delay={i * 60 + 80}>
              <div className="rounded-xl border border-edge/50 p-6 sm:p-7">
                <h3 className="mb-2 text-base font-semibold leading-snug text-title">
                  {c.title}
                </h3>
                <p className="mb-3 text-sm leading-relaxed text-body">{c.description}</p>
                <p className="min-w-0 font-mono text-[11px] break-words text-label/70">
                  {c.witnesses}
                </p>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </Section>
  );
}
