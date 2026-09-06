#!/usr/bin/env python3
"""Build the slide deck HTML from the Marp markdown.

    python3 docs/deck/build.py docs/pusher-incentives-slides.md -o /tmp/deck.html

The markdown is the source. It stays a valid Marp deck — `marp-cli` renders it
to PDF unchanged — and this script produces the self-contained HTML version
with keyboard navigation. Inline markdown, GFM tables and column alignment are
handled by `md2html` (md4c), not by anything here.

Four directives, all HTML comments, so every markdown renderer ignores them:

    <!-- title -->              this slide is the title card
    <!-- part: Part one -->     section divider, with that kicker
    <!-- eyebrow: Theory -->    the small label above the heading
    <!-- hazard -->             the next blockquote is the warning colour

Blockquotes become the accent callout. Tables are wrapped so wide ones scroll
inside the slide rather than pushing the page sideways.
"""
import argparse
import html
import pathlib
import re
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).parent


def render(md: str) -> str:
    """Markdown fragment -> HTML, via md2html."""
    if not md.strip():
        return ""
    out = subprocess.run(
        ["md2html", "--github"], input=md, capture_output=True, text=True, check=True
    ).stdout
    # Wide content scrolls in its own box; the slide itself never does.
    out = re.sub(r"(<table>.*?</table>)", r'<div class="scroll">\1</div>', out, flags=re.S)
    return out.strip()


def slide(body: str, index: int) -> str:
    """One markdown slide -> one <section>."""
    title = "<!-- title -->" in body
    part = re.search(r"<!--\s*part:\s*(.*?)\s*-->", body)
    eyebrow = re.search(r"<!--\s*eyebrow:\s*(.*?)\s*-->", body)
    body = re.sub(r"<!--\s*(title|part:.*?|eyebrow:.*?)\s*-->", "", body)

    # `<!-- hazard -->` tags the blockquote that follows it. md2html drops
    # comments, so the flag rides through as a sentinel inside the quote.
    body = re.sub(r"<!--\s*hazard\s*-->\s*\n+>", "> @@HZ@@", body)
    out = render(body)

    # Blockquote is the deck's callout. Unwrap its paragraph so the callout is
    # one styled block rather than a quote wrapping a paragraph.
    def callout(m: re.Match) -> str:
        inner = re.sub(r"</?p>", "", m.group(1)).strip()
        cls = "claim"
        if inner.startswith("@@HZ@@"):
            cls, inner = "claim hz", inner[len("@@HZ@@"):].strip()
        return f'<div class="{cls}">{inner}</div>'

    out = re.sub(r"<blockquote>(.*?)</blockquote>", callout, out, flags=re.S)

    num = f'<div class="num">{index:02d}</div>'

    if title:
        h1 = re.search(r"<h1>(.*?)</h1>", out, re.S)
        h2 = re.search(r"<h2>(.*?)</h2>", out, re.S)
        meta = re.search(r"<p><em>(.*?)</em></p>", out, re.S)
        return (
            '<section class="slide title on">\n'
            '    <div class="rule"></div>\n'
            f"    <h1>{h1.group(1) if h1 else ''}</h1>\n"
            f'    <p class="lede sub">{h2.group(1) if h2 else ""}.</p>\n'
            f'    <div class="meta">{meta.group(1) if meta else ""}</div>\n'
            "  </section>"
        )

    if part:
        h1 = re.search(r"<h1>(.*?)</h1>", out, re.S)
        return (
            '<section class="slide part">\n'
            f'    <div class="kicker">{html.escape(part.group(1))}</div>\n'
            f"    <h2>{h1.group(1) if h1 else ''}</h2>\n"
            f"    {num}\n"
            "  </section>"
        )

    # A slide's `#` heading is an <h2> visually — <h1> is reserved for the deck.
    out = re.sub(r"<h1>(.*?)</h1>", r"<h2>\1</h2>", out, flags=re.S)
    eb = (
        f'<div class="eyebrow">{eyebrow.group(1)}</div>\n    '
        if eyebrow
        else ""
    )
    # Everything that is not a heading, table, code block or callout is prose.
    out = re.sub(
        r"((?:<(?:p|ul|ol)>.*?</(?:p|ul|ol)>\s*)+)",
        lambda m: f'<div class="body">{m.group(1).strip()}</div>',
        out,
        flags=re.S,
    )
    return f'<section class="slide">\n    {eb}{out}\n    {num}\n  </section>'


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("source", type=pathlib.Path)
    ap.add_argument("-o", "--output", type=pathlib.Path, required=True)
    args = ap.parse_args()

    if not shutil.which("md2html"):
        print("md2html not found (md4c). Install it, or render with marp-cli.", file=sys.stderr)
        return 1

    text = args.source.read_text()
    # Drop the Marp front matter; it configures marp-cli, not this.
    text = re.sub(r"\A---\n.*?\n---\n", "", text, flags=re.S)
    title = "Paying for relay — an incentive layer for hoverfly pushers"

    slides = [s for s in re.split(r"\n---\n", text) if s.strip()]
    sections = "\n\n  ".join(slide(s, i + 1) for i, s in enumerate(slides))

    args.output.write_text(
        f"<title>{title}</title>\n\n"
        + (HERE / "shell.css.html").read_text()
        + f'\n<div class="stage" id="stage">\n\n  {sections}\n\n</div>\n\n'
        + (HERE / "shell.bar.html").read_text()
        + "\n"
        + (HERE / "shell.js.html").read_text()
        + "\n"
    )
    print(f"{len(slides)} slides -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
