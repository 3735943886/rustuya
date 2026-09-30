#!/usr/bin/env python3
"""Validate local links and version navigation in the rendered Pages artifact."""
from html.parser import HTMLParser
from pathlib import Path
import sys
from urllib.parse import unquote, urljoin, urlsplit


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.links = []
        self.ids = set()
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        for attr in ("href", "src"):
            if attrs.get(attr):
                self.links.append(attrs[attr])


root = Path(sys.argv[1]).resolve()
base = "/rustuya/"
origin = "https://3735943886.github.io"
pages = {p: Page(p.read_text()) for p in root.rglob("*.html")}
errors = []
for path, page in pages.items():
    current = origin + base + path.relative_to(root).as_posix()
    for link in page.links:
        url = urlsplit(urljoin(current, link))
        if url.scheme not in ("http", "https") or url.netloc != urlsplit(origin).netloc:
            continue
        if not url.path.startswith(base):
            errors.append(f"{path.relative_to(root)}: link escapes site base: {link}")
            continue
        target = root / unquote(url.path[len(base):])
        if target.is_dir():
            target /= "index.html"
        if not target.is_file():
            errors.append(f"{path.relative_to(root)}: missing target: {link}")
        elif url.fragment and target in pages and unquote(url.fragment) not in pages[target].ids:
            errors.append(f"{path.relative_to(root)}: missing anchor: {link}")

for name in ("index.html", "0.3/index.html", "0.3/python-api.html", "python-api.html"):
    path = root / name
    if path not in pages:
        errors.append(f"Missing required page: {name}")
        continue
    if base not in pages[path].links or base + "0.3/" not in pages[path].links:
        errors.append(f"Missing version navigation: {name}")
if "Rust async/sync API and Python bindings" not in (root / "index.html").read_text():
    errors.append("The current home page must identify the 0.3 archive")
if "Archived documentation for rustuya 0.3" not in (root / "0.3/index.html").read_text():
    errors.append("The archive must identify its version")
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print(f"Verified {len(pages)} HTML pages: internal links, anchors and version navigation.")
