import {
  BookOpen,
  ExternalLink,
  Github,
  Newspaper,
  ShieldCheck,
} from "lucide-react";

const linkGroups = [
  {
    title: "Resources",
    links: [
      {
        label: "This Week in MicroVMs",
        href: "https://this-week-in-microvms.com",
      },
      { label: "Nix for mvm", href: "/getting-started/nix-for-mvm/" },
      { label: "Architecture", href: "/architecture/overview/" },
      { label: "GitHub", href: "https://github.com/tinylabscom/mvm" },
    ],
  },
  {
    title: "Explore",
    links: [
      { label: "Architecture", href: "/architecture/overview/" },
      { label: "Nix and OCI", href: "/guides/nix-and-oci/" },
      { label: "Threat model", href: "/security/threat-model/" },
      { label: "Security claims", href: "/security/claim-ledger/" },
    ],
  },
  {
    title: "Community",
    links: [
      {
        label: "This Week in MicroVMs",
        href: "https://this-week-in-microvms.com",
      },
      { label: "GitHub", href: "https://github.com/tinylabscom/mvm" },
      { label: "Issues", href: "https://github.com/tinylabscom/mvm/issues" },
      {
        label: "Releases",
        href: "https://github.com/tinylabscom/mvm/releases",
      },
    ],
  },
];

const socialLinks = [
  { label: "GitHub", href: "https://github.com/tinylabscom/mvm", icon: Github },
  { label: "Blog", href: "/blog/", icon: Newspaper },
  { label: "Docs", href: "/getting-started/installation/", icon: BookOpen },
  {
    label: "MicroVMs weekly",
    href: "https://this-week-in-microvms.com",
    icon: ShieldCheck,
  },
];

function withBase(path: string, base: string) {
  if (path.startsWith("http")) return path;
  return `${base}${path.replace(/^\//, "")}`;
}

export function Footer() {
  const rawBase = import.meta.env.BASE_URL;
  const base = rawBase.endsWith("/") ? rawBase : `${rawBase}/`;

  return (
    <footer className="landing-footer border-t border-edge bg-canvas pt-16 lg:pt-20">
      <div className="landing-footer__inner mx-auto max-w-6xl px-6 pb-10 sm:px-8 lg:pb-12">
        <div className="grid gap-12 sm:grid-cols-2 lg:grid-cols-[minmax(0,1.35fr)_repeat(3,minmax(0,1fr))] lg:gap-16">
          <div className="max-w-xs">
            <a
              href={base}
              className="font-mono text-3xl font-bold text-title no-underline"
            >
              mvm
            </a>
            <p className="mt-5 max-w-sm text-base leading-7 text-body">
              Secure, reproducible microVMs for running untrusted code without
              turning every developer into an infrastructure operator.
            </p>
          </div>

          {linkGroups.map((group) => (
            <nav key={group.title} aria-label={group.title}>
              <h2 className="text-sm font-semibold text-title">
                {group.title}
              </h2>
              <ul className="mt-5 space-y-3">
                {group.links.map((link) => {
                  const external = link.href.startsWith("http");
                  return (
                    <li key={link.label}>
                      <a
                        href={withBase(link.href, base)}
                        target={external ? "_blank" : undefined}
                        rel={external ? "noopener" : undefined}
                        className="inline-flex items-center gap-1 text-sm leading-6 text-body no-underline transition hover:text-accent"
                      >
                        <span>{link.label}</span>
                        {external && (
                          <ExternalLink
                            size={13}
                            strokeWidth={2}
                            className="shrink-0"
                          />
                        )}
                      </a>
                    </li>
                  );
                })}
              </ul>
            </nav>
          ))}
        </div>
      </div>

      <div className="mt-16 border-t border-edge lg:mt-20">
        <div className="landing-footer__inner mx-auto flex max-w-6xl flex-col gap-4 px-6 py-8 text-sm text-label sm:px-8 lg:flex-row lg:items-center lg:justify-between">
          <p>Built by Tiny Labs.</p>
          <nav className="flex flex-wrap gap-5" aria-label="Social links">
            {socialLinks.map(({ label, href, icon: Icon }) => {
              const target = withBase(href, base);
              const external = href.startsWith("http");
              return (
                <a
                  key={label}
                  href={target}
                  target={external ? "_blank" : undefined}
                  rel={external ? "noopener" : undefined}
                  className="inline-flex text-label transition hover:text-accent"
                  aria-label={label}
                >
                  <Icon size={18} strokeWidth={2} />
                </a>
              );
            })}
          </nav>
        </div>
      </div>
    </footer>
  );
}
