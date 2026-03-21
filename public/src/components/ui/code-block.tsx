import { Highlight, Prism, type PrismTheme } from "prism-react-renderer";

// Register bash grammar (not included in prism-react-renderer by default)
Prism.languages.bash = {
  comment: { pattern: /(^|[^"{\\$])#.*/, lookbehind: true },
  string: {
    pattern: /(["'])(?:\\[\s\S]|\$\([^)]+\)|\$(?!\()|`[^`]+`|(?!\1)[^\\`$])*\1/,
    greedy: true,
  },
  variable: /\$\{?\w+\}?/,
  function: {
    pattern: /(^|[\s;|&])(?:mvmctl|curl|nix|sudo|sh)\b/,
    lookbehind: true,
  },
  keyword: {
    pattern:
      /(^|[\s;|&])(?:if|then|else|elif|fi|for|while|do|done|case|esac|function|return|in)\b/,
    lookbehind: true,
  },
  builtin: {
    pattern: /(^|[\s;|&])(?:echo|cd|export|source|eval|exec|set)\b/,
    lookbehind: true,
  },
  operator: /&&|\|\||[<>]=?|[!=]=?/,
  punctuation: /[;|&(){}\[\]]/,
  number: { pattern: /(^|[\s=])(\d+)\b/, lookbehind: true },
};

// Register nix grammar
Prism.languages.nix = {
  comment: { pattern: /#.*|\/\*[\s\S]*?\*\//, greedy: true },
  string: { pattern: /"(?:[^"\\]|\\.)*"/, greedy: true },
  interpolation: { pattern: /\$\{[^}]+\}/, greedy: true },
  keyword: /\b(?:let|in|if|then|else|with|inherit|import|rec|assert)\b/,
  function: /\b(?:mkGuest|mkDerivation|mkShell|fetchurl|fetchgit)\b/,
  boolean: /\b(?:true|false|null)\b/,
  number: /\b\d+\b/,
  operator: /[=!<>]=?|&&|\|\||\/\/|\+\+|->|\?/,
  punctuation: /[{}()\[\];.,:#@]/,
  property: { pattern: /\b[\w-]+(?=\s*[=.])/, greedy: true },
};

const theme: PrismTheme = {
  plain: {
    color: "var(--color-heading)",
    backgroundColor: "var(--color-page)",
  },
  styles: [
    {
      types: ["comment"],
      style: { color: "var(--color-muted)", fontStyle: "italic" as const },
    },
    {
      types: ["string", "attr-value"],
      style: { color: "var(--color-green)" },
    },
    {
      types: ["keyword", "builtin", "important"],
      style: { color: "var(--color-accent)" },
    },
    {
      types: ["function"],
      style: { color: "var(--color-nix)" },
    },
    {
      types: ["operator", "punctuation"],
      style: { color: "var(--color-amber)" },
    },
    {
      types: ["variable", "interpolation"],
      style: { color: "var(--color-rust)" },
    },
    {
      types: ["property"],
      style: { color: "var(--color-accent-hover)" },
    },
    {
      types: ["number", "boolean", "constant"],
      style: { color: "var(--color-accent-hover)" },
    },
  ],
};

export function CodeBlock({ code, language }: { code: string; language: string }) {
  return (
    <Highlight theme={theme} code={code} language={language}>
      {({ tokens, getLineProps, getTokenProps }) => (
        <div className="overflow-hidden rounded-xl border border-edge bg-raised shadow-lg shadow-black/20">
          {/* Terminal header bar */}
          <div className="flex items-center gap-2 border-b border-edge px-4 py-3">
            <span className="h-3 w-3 rounded-full bg-dot-close opacity-80" />
            <span className="h-3 w-3 rounded-full bg-dot-minimize opacity-80" />
            <span className="h-3 w-3 rounded-full bg-dot-expand opacity-80" />
            <span className="ml-3 text-xs font-medium text-label">{language}</span>
          </div>
          {/* Code area */}
          <pre className="overflow-x-auto bg-canvas p-6 font-mono text-sm leading-relaxed sm:p-8">
            <code className="grid" style={{ gridTemplateColumns: "2.5rem 1fr" }}>
              {tokens.map((line, i) => (
                <div key={i} {...getLineProps({ line })} className="contents">
                  <span className="select-none text-right text-label/40 pr-4">
                    {i + 1}
                  </span>
                  <span className="overflow-x-auto">
                    {line.map((token, key) => (
                      <span key={key} {...getTokenProps({ token })} />
                    ))}
                  </span>
                </div>
              ))}
            </code>
          </pre>
        </div>
      )}
    </Highlight>
  );
}
