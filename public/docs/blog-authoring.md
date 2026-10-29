# Blog sharing

Every post in `src/content/blog/` must include a `shareHook` string in its
frontmatter: a short, post-specific reason to read and share the article.
The content schema rejects missing, blank, or over-240-character hooks at build
time. Keep the hook short enough to leave room for the article URL.

The shared post template renders X, LinkedIn, Facebook, and Reddit buttons using
`react-share`. X uses the hook as the post text and Reddit as the submission
title. Facebook and LinkedIn accept the article URL but control their own
composer text; readers can add their own commentary there. No social SDK or
tracking widget is loaded.

After adding a post, run `pnpm build` followed by
`node --test tests/blog-sharing.test.mjs` from `public/`.
