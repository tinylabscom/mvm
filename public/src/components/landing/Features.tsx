import { Card, CardHeader, CardTitle, CardDescription } from "../ui/card";

const features = [
  {
    title: "Three-Layer Stack",
    description:
      "CLI on your host. On macOS or Linux without KVM, Lima provides /dev/kvm automatically. Native Linux skips Lima entirely. Firecracker runs your workloads.",
  },
  {
    title: "Nix-Based Builds",
    description:
      "Reproducible microVM images from Nix flakes. Cached builds — rebuilds are near-instant.",
  },
  {
    title: "Headless MicroVMs",
    description:
      "No SSH, ever. MicroVMs communicate via Firecracker vsock. The guest agent handles lifecycle.",
  },
  {
    title: "Integration Health",
    description:
      "Workloads register health checks via drop-in JSON. The guest agent polls and reports status.",
  },
  {
    title: "Templates & Registry",
    description:
      "Build reusable base images, version them, share via S3-compatible registry.",
  },
  {
    title: "Security Posture",
    description:
      "Evaluate jailer isolation, seccomp filters, network isolation, and audit logging.",
  },
];

export function Features() {
  return (
    <section className="w-full border-y border-edge/50 bg-raised px-6 py-28 sm:px-8 lg:py-36">
      <div className="mx-auto max-w-6xl">
        <h2 className="mb-16 text-center text-2xl font-semibold text-title sm:text-3xl lg:mb-20">
          How It Works
        </h2>
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3 sm:gap-8">
          {features.map((f) => (
            <Card key={f.title}>
              <CardHeader>
                <CardTitle>{f.title}</CardTitle>
                <CardDescription>{f.description}</CardDescription>
              </CardHeader>
            </Card>
          ))}
        </div>
      </div>
    </section>
  );
}
