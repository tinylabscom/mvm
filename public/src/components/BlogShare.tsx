import {
  FacebookShareButton,
  LinkedinShareButton,
  RedditShareButton,
  XShareButton,
} from "react-share";

export default function BlogShare({ url, hook }: { url: string; hook: string }) {
  return (
    <nav aria-label="Share this post" className="flex flex-wrap items-center gap-4 py-4">
      <span>Share this post:</span>
      <XShareButton url={url} text={hook} aria-label="Share on X">X</XShareButton>
      <LinkedinShareButton url={url} aria-label="Share on LinkedIn">LinkedIn</LinkedinShareButton>
      <FacebookShareButton url={url} aria-label="Share on Facebook">Facebook</FacebookShareButton>
      <RedditShareButton url={url} shareTitle={hook} aria-label="Share on Reddit">Reddit</RedditShareButton>
    </nav>
  );
}
