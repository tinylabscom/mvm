// CTABanner is hidden for now — restore its import alongside the
// commented-out <CTABanner /> below.
// import { CTABanner } from "./CTABanner";
import { ExecutionContract } from "./ExecutionContract";
import { Footer } from "./Footer";
import { Hero } from "./Hero";
// Quickstart is hidden for now — restore its import alongside the
// commented-out <Quickstart /> below.
// import { Quickstart } from "./Quickstart";
import { RegulatorsNow } from "./RegulatorsNow";
import { RequestAccess } from "./RequestAccess";
import { RiskControl } from "./RiskControl";
import { WhyNow } from "./WhyNow";
// DemoTeaser is hidden for now — restore its import alongside the
// commented-out <DemoTeaser /> below.
// import { DemoTeaser } from "./DemoTeaser";
// Positioning is hidden for now — restore its import alongside the
// commented-out <Positioning /> below.
// import { Positioning } from "./Positioning";

// The landing page tells the pitch story — one beat per section, in the
// pitch script's order. The section order IS the argument; do not reorder
// or insert a section without re-reading the pitch script (the 3–4 minute
// spoken pitch is the brief for this page — the reshape-brief.md /
// layout-match-report.md files the old comment cited no longer exist in
// the repo).
//   1. Hero              — the claim ("run code you can't fully trust"),
//                          the box sentence, and the boundary diagram.
//   2. Why now (problem)  — AI is proliferating and so are exploits; teams
//                          want to go hands-off and fear it, because the
//                          non-determinism that makes agents useful is
//                          exactly what makes them dangerous. The
//                          emotional core.
//      2x. Demo teaser     — browser sandbox. HIDDEN for now, not removed.
//   3. Execution contract — the box is table stakes, the contract is the
//                          product: declare → sign → proof. Six layers,
//                          plus the link out to /how-it-works.
//   4. Risk control       — control for the people who own the risk:
//                          start/stop, kill on violation, and the audit
//                          trail compliance asks for.
//   5. Regulators         — the timing argument's second half: regulators
//                          want proof of what agents did and were allowed
//                          to do, and the contract is that proof.
//   6. Quickstart         — the builder off-ramp, after the story is
//                          told: install (moved down from the hero) and
//                          file-in, running-microVM-out.
//                          HIDDEN for now (commented out below), not
//                          removed — note this also hides InstallTabs,
//                          so the landing page has no install command.
//      6x. Positioning     — HIDDEN for now, not removed.
//   7. Request access     — the design-partner form (#request-access, the
//                          hero's button anchors here).
//   8. Close + footer     — the vision (controls upstream, to the moment
//                          a prompt is written) and the closing line.
//                          HIDDEN for now (commented out below), not
//                          removed — the page currently ends on the
//                          request-access form and the footer.
// The mechanism/evidence sections (WhyMicrovm, LaunchPerf,
// DeploymentTiers, Backends, FAQ) moved to /how-it-works — see
// HowItWorks.tsx — linked from the contract section and the header nav.
export function Landing() {
  return (
    <div className="min-h-screen w-full bg-canvas">
      <Hero />
      {/* The demo teaser (browser sandbox) is hidden for now, not
          deleted — restore by uncommenting here and its import above. */}
      {/* <DemoTeaser /> */}
      <WhyNow />
      <ExecutionContract />
      <RiskControl />
      <RegulatorsNow />
      {/* Quickstart (install + file-in, microVM-out) is hidden for
          now, not deleted — restore by uncommenting here and its
          import above. */}
      {/* <Quickstart /> */}
      {/* Positioning ("one project. three ways to drive it.") is hidden for
          now, not deleted — restore by uncommenting here and re-adding its
          entry to the section-order comment above. */}
      {/* <Positioning /> */}
      <RequestAccess />
      {/* The closing band ("ai may never be fully predictable" + the
          vision paragraph) is hidden for now, not deleted — restore
          by uncommenting here and its import above. */}
      {/* <CTABanner /> */}
      <Footer />
    </div>
  );
}
