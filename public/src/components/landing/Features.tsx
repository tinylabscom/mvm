import { Card, CardHeader, CardTitle, CardDescription } from "../ui/card";

const features = [
  {
    title: "Three-Layer Stack",
    description:
      "CLI on your host, Lima provides /dev/kvm on macOS, Firecracker runs microVMs inside it.",
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
    <section className="px-6 py-24 sm:px-8">
      <div className="mx-auto max-w-5xl">
        <h2 className="mb-12 text-center text-2xl font-semibold text-heading sm:text-3xl">
          How It Works
        </h2>
        <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3 sm:gap-6">
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
