"""Scraper demo (offline, local fixture).  From the repo root:
    .venv/Scripts/python caisp-course/ch2-understanding-and-attacking-llms/labs/05-web-scraper/demo.py

Optional network mode (only the URL you pass; robots.txt respected):
    .venv/Scripts/python caisp-course/ch2-understanding-and-attacking-llms/labs/05-web-scraper/demo.py --url https://example.com/
"""

import sys
from pathlib import Path

from scraper import fetch, naive_text, parse_file, parse_html, sanitize_for_llm, summarize

FIXTURE = Path(__file__).parent / "fixtures" / "product.html"


def show(page) -> None:
    print("title   :", page.title)
    print("headings:", page.headings)
    print("links   :", page.links)
    print("visible :", len(page.visible_text), "text blocks")
    print("hidden  :", len(page.hidden_text), "blocks;", "comments:", len(page.comments))


def main() -> None:
    if "--url" in sys.argv:
        url = sys.argv[sys.argv.index("--url") + 1]
        page = parse_html(fetch(url))
        show(page)
        text, findings = sanitize_for_llm(page)
        print("findings:", findings)
        print(summarize(text))
        return

    page = parse_file(str(FIXTURE))
    print("== 1. What the parser extracts ==")
    show(page)
    print("\n== 2. Hidden content the browser would not show ==")
    for t in page.hidden_text + page.comments:
        print(" -", t)
    print("\n== 3. Careless pipeline: raw text -> LLM ==")
    print(summarize(naive_text(page)))
    print("\n== 4. Sanitized pipeline ==")
    clean, findings = sanitize_for_llm(page)
    for f in findings:
        print(" *", f)
    print(summarize(clean))


if __name__ == "__main__":
    main()
