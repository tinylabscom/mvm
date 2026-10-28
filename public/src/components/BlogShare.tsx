import {
  FacebookShareButton,
  FacebookIcon,
  LinkedinShareButton,
  LinkedinIcon,
  RedditShareButton,
  RedditIcon,
  XShareButton,
  XIcon,
} from "react-share";

export default function BlogShare({ url, hook }: { url: string; hook: string }) {
  return (
    <nav aria-label="Share this post" className="blog-share">
      <XShareButton url={url} text={hook} aria-label="Share on X" htmlTitle="Share on X" resetButtonStyle={false}>
        <XIcon size={16} color="currentColor" aria-hidden="true" />
      </XShareButton>
      <LinkedinShareButton url={url} aria-label="Share on LinkedIn" htmlTitle="Share on LinkedIn" resetButtonStyle={false}>
        <LinkedinIcon size={16} color="currentColor" aria-hidden="true" />
      </LinkedinShareButton>
      <FacebookShareButton url={url} aria-label="Share on Facebook" htmlTitle="Share on Facebook" resetButtonStyle={false}>
        <FacebookIcon size={16} color="currentColor" aria-hidden="true" />
      </FacebookShareButton>
      <RedditShareButton url={url} shareTitle={hook} aria-label="Share on Reddit" htmlTitle="Share on Reddit" resetButtonStyle={false}>
        <RedditIcon size={16} color="currentColor" aria-hidden="true" />
      </RedditShareButton>
    </nav>
  );
}
