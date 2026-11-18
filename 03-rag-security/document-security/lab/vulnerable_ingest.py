"""A deliberately vulnerable RAG ingestion pipeline.

It takes a file from a connector (SharePoint, wiki, HR system, user upload), turns it
into text, splits it into chunks and adds the chunks to the index. It does what many
first prototypes do: "make it work for every file, as fast as possible".

DO NOT copy this pattern. Every line marked VULN is one of the mistakes this lab
teaches you to find.

Run the scorecard from the repository root:
    python 03-rag-security/document-security/lab/demo.py
"""

from __future__ import annotations

import io
import posixpath
import re
import zipfile
from dataclasses import dataclass, field

EXTRACT_DIR = "/srv/ingest/tmp"
CHUNK_WORDS = 80


@dataclass
class Chunk:
    text: str
    metadata: dict


@dataclass
class IngestResult:
    status: str  # "indexed" | "rejected" | "quarantined"
    reasons: list[str] = field(default_factory=list)


def parse_front_matter(text: str) -> tuple[dict, str]:
    """Read a simple '---' key: value '---' header at the top of a text file."""
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---\n", 4)
    if end == -1:
        return {}, text
    meta = {}
    for line in text[4:end].splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            meta[key.strip()] = value.strip()
    return meta, text[end + 5:]


def html_to_text(html: str) -> str:
    # VULN 1: tag stripping keeps ALL text, including text a human can never see
    # (display:none, white-on-white, font-size:0). The model sees what the reviewer didn't.
    return " ".join(re.sub(r"<[^>]+>", " ", html).split())


def chunk(text: str) -> list[str]:
    words = text.split()
    return [" ".join(words[i:i + CHUNK_WORDS]) for i in range(0, len(words), CHUNK_WORDS)]


class VulnerableIngestor:
    def __init__(self) -> None:
        self.chunks: list[Chunk] = []
        self.bytes_expanded = 0          # how much data archives expanded into
        self.extracted_paths: list[str] = []

    def ingest(self, filename: str, content: bytes, source: str) -> IngestResult:
        # VULN 2: the file type is decided by the extension. No magic-byte check,
        # no size limit, no allowlist of types. An .exe called notes.txt is "text".
        ext = filename.rsplit(".", 1)[-1].lower()

        if ext == "zip":
            # VULN 3: archives are expanded completely, with no limit on size,
            # member count or compression ratio, and member paths are trusted.
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                for info in archive.infolist():
                    data = archive.read(info)
                    self.bytes_expanded += len(data)
                    target = posixpath.normpath(posixpath.join(EXTRACT_DIR, info.filename))
                    self.extracted_paths.append(target)  # where a real extractor would write
                    self.ingest(info.filename, data, source)
            return IngestResult("indexed", ["archive expanded"])

        text = content.decode("utf-8", errors="ignore")  # binary junk becomes "text"
        meta, text = parse_front_matter(text)
        if ext in ("html", "htm"):
            text = html_to_text(text)

        # VULN 4: the document decides its own trust level and tenant. Anyone who can
        # upload a file can write "trust: official" at the top of it.
        trust = meta.get("trust", "internal")
        tenant = meta.get("tenant", "acme")

        # VULN 5: no normalization (zero-width characters stay), no scan for
        # instructions, and every source is indexed straight away - uploads included.
        # VULN 6: no PII detection or redaction. Whatever is in the file is now
        # searchable by everyone who can use the assistant.
        # VULN 7: no provenance: no hash, no connector, no parser version. When a bad
        # answer appears, nobody can trace which file or source it came from.
        for piece in chunk(text):
            self.chunks.append(Chunk(piece, {"filename": filename, "trust": trust, "tenant": tenant}))
        return IngestResult("indexed")
