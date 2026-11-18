"""The same ingestion pipeline, rebuilt with layered controls.

Each layer can be switched off so you can prove which layer stopped which attack:

    L1  File validation: size limit, type decided by magic bytes (not the extension),
        allowlist of types, extension must match the real content.          (hard)
    L2  Archive limits: member count, real expanded size, compression ratio,
        no nested archives, no "../" or absolute member paths.               (hard)
    L3  Source trust: tenant and trust label come from the connector registry,
        never from the document. Untrusted sources go to quarantine for review. (hard)
    L4  Sanitize: drop hidden HTML (display:none, comments, scripts...) and
        normalize Unicode (NFKC, remove zero-width / format characters).     (hard, known tricks only)
    L5  Injection scan: instruction-like text -> quarantine for a human.     (soft, bypassable)
    L6  PII redaction before indexing (emails, phones, national IDs).        (hard for known formats)
    L7  Provenance on every chunk: source, sha256, parser version, time, and
        an audit log of every decision.                                      (process)

Suspicious files are QUARANTINED (kept for review, not indexed), not silently dropped:
a security team needs to see them, and a false positive needs a way back in.
"""

from __future__ import annotations

import hashlib
import io
import re
import unicodedata
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser

PARSER_VERSION = "lab-parser-1.0"
CHUNK_WORDS = 80

MAX_FILE_BYTES = 1_000_000
MAX_ARCHIVE_MEMBERS = 20
MAX_EXPANDED_BYTES = 5_000_000
MAX_COMPRESSION_RATIO = 100
ALLOWED_TYPES = {"text", "html", "zip"}
EXTENSION_TYPES = {"txt": "text", "md": "text", "csv": "text", "html": "html", "htm": "html", "zip": "zip"}

# Magic bytes: the first bytes of a file say what it really is.
MAGIC = [
    (b"PK\x03\x04", "zip"),
    (b"%PDF-", "pdf"),
    (b"MZ", "executable"),          # Windows PE
    (b"\x7fELF", "executable"),     # Linux ELF
    (b"\x1f\x8b", "gzip"),
]


@dataclass(frozen=True)
class SourcePolicy:
    tenant: str
    trust: str
    auto_index: bool  # False -> a human reviews the file before it can be indexed


# L3: the ONLY place trust and tenant come from. Owned by the platform team.
SOURCES = {
    "sharepoint-policies": SourcePolicy("acme", "official", True),
    "wiki": SourcePolicy("acme", "internal", True),
    "hr-system": SourcePolicy("acme", "confidential", True),
    "upload": SourcePolicy("acme", "untrusted", False),
}

INJECTION_PATTERNS = [
    re.compile(r"\b(ignore|disregard)\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+instructions", re.I),
    re.compile(r"\bsystem override\b", re.I),
    re.compile(r"\byou are now (in )?(developer|debug|admin) mode", re.I),
    re.compile(r"\bnew instructions\s*:", re.I),
    re.compile(r"CALL_TOOL", re.I),
    re.compile(r"\b(note|message) (for|to) (ai|llm|the assistant|assistants)", re.I),
]

PII_PATTERNS = [
    ("NATIONAL_ID", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("PHONE", re.compile(r"(?:\+\d{1,3}[\s-])?\b\d{3}[\s.-]\d{3}[\s.-]\d{4}\b")),
]

HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d])|opacity\s*:\s*0(?![.\d])"
    r"|color\s*:\s*(#fff\b|#ffffff\b|white\b)",
    re.I,
)
VOID_TAGS = {"br", "img", "hr", "meta", "link", "input", "source", "wbr", "area", "base", "col", "embed"}
NEVER_CONTENT_TAGS = {"script", "style", "template", "noscript"}


@dataclass
class Chunk:
    text: str
    metadata: dict


@dataclass
class IngestResult:
    status: str  # "indexed" | "rejected" | "quarantined"
    reasons: list[str] = field(default_factory=list)


class _VisibleTextParser(HTMLParser):
    """Split HTML into text a person would see, and text they would not."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, bool]] = []
        self.visible: list[str] = []
        self.hidden: list[str] = []

    def _hidden_now(self) -> bool:
        return bool(self.stack) and self.stack[-1][1]

    def handle_starttag(self, tag, attrs):
        if tag in VOID_TAGS:
            return
        a = {k: (v or "") for k, v in attrs}
        hides = (
            tag in NEVER_CONTENT_TAGS
            or "hidden" in a
            or a.get("aria-hidden", "").lower() == "true"
            or bool(HIDDEN_STYLE_RE.search(a.get("style", "")))
        )
        self.stack.append((tag, self._hidden_now() or hides))

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                return

    def handle_data(self, data):
        (self.hidden if self._hidden_now() else self.visible).append(data)

    def handle_comment(self, data):
        self.hidden.append(data)


def sniff_type(content: bytes) -> str:
    for magic, kind in MAGIC:
        if content.startswith(magic):
            return kind
    if b"\x00" in content:
        return "binary"
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return "binary"
    head = text.lstrip()[:200].lower()
    return "html" if head.startswith(("<html", "<!doctype html")) else "text"


def normalize_unicode(text: str) -> tuple[str, int]:
    """NFKC-normalize and remove invisible format characters. Returns (text, removed)."""
    text = unicodedata.normalize("NFKC", text)
    kept = [ch for ch in text if unicodedata.category(ch) != "Cf"]
    return "".join(kept), len(text) - len(kept)


def redact_pii(text: str) -> tuple[str, list[str]]:
    found = []
    for label, pattern in PII_PATTERNS:
        text, n = pattern.subn(f"[REDACTED:{label}]", text)
        found += [label] * n
    return text, found


def strip_markup_comments(text: str) -> tuple[str, list[str]]:
    comments = re.findall(r"<!--(.*?)-->", text, re.S)
    return re.sub(r"<!--.*?-->", " ", text, flags=re.S), comments


def chunk(text: str) -> list[str]:
    words = text.split()
    return [" ".join(words[i:i + CHUNK_WORDS]) for i in range(0, len(words), CHUNK_WORDS)]


class SecureIngestor:
    def __init__(
        self,
        *,
        validate_files: bool = True,
        archive_limits: bool = True,
        enforce_source_trust: bool = True,
        strip_hidden: bool = True,
        normalize: bool = True,
        scan_injection: bool = True,
        redact: bool = True,
    ) -> None:
        self.validate_files = validate_files
        self.archive_limits = archive_limits
        self.enforce_source_trust = enforce_source_trust
        self.strip_hidden = strip_hidden
        self.normalize = normalize
        self.scan_injection = scan_injection
        self.redact = redact
        self.chunks: list[Chunk] = []
        self.quarantine: list[dict] = []
        self.audit: list[dict] = []      # L7: every decision, with the file hash
        self.bytes_expanded = 0

    # --- helpers ----------------------------------------------------------------
    def _decide(self, filename: str, digest: str, status: str, reasons: list[str]) -> IngestResult:
        self.audit.append({"filename": filename, "sha256": digest, "status": status, "reasons": reasons})
        return IngestResult(status, reasons)

    # --- L1 --------------------------------------------------------------------
    def _validate(self, filename: str, content: bytes) -> tuple[str | None, str]:
        """Return (error, real_type)."""
        real = sniff_type(content)
        if not self.validate_files:
            return None, real
        if len(content) > MAX_FILE_BYTES:
            return f"file too large ({len(content)} bytes > {MAX_FILE_BYTES})", real
        if real not in ALLOWED_TYPES:
            return f"file type '{real}' is not allowed", real
        claimed = EXTENSION_TYPES.get(filename.rsplit(".", 1)[-1].lower())
        if claimed is None:
            return "extension is not on the allowlist", real
        text_like = {"text", "html"}
        if claimed != real and not (claimed in text_like and real in text_like):
            return f"extension says '{claimed}' but content is '{real}'", real
        return None, "html" if "html" in (claimed, real) else real

    # --- L2 --------------------------------------------------------------------
    def _expand_archive(self, content: bytes) -> tuple[str | None, list[tuple[str, bytes]]]:
        members: list[tuple[str, bytes]] = []
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            infos = archive.infolist()
            if self.archive_limits:
                if len(infos) > MAX_ARCHIVE_MEMBERS:
                    return f"too many archive members ({len(infos)})", []
                for info in infos:
                    name = info.filename.replace("\\", "/")
                    if name.startswith("/") or ".." in name.split("/") or re.match(r"^[A-Za-z]:", name):
                        return f"unsafe member path '{info.filename}'", []
                    if info.filename.lower().endswith(".zip"):
                        return "nested archives are not allowed", []
                    if info.file_size / max(info.compress_size, 1) > MAX_COMPRESSION_RATIO:
                        return f"compression ratio too high for '{info.filename}'", []
                if sum(i.file_size for i in infos) > MAX_EXPANDED_BYTES:
                    return "declared expanded size too large", []
            budget = MAX_EXPANDED_BYTES if self.archive_limits else None
            for info in infos:
                if info.is_dir():
                    continue
                with archive.open(info) as fh:
                    # Headers can lie about sizes, so cap the bytes we actually read.
                    data = fh.read(budget + 1 if budget is not None else -1)
                self.bytes_expanded += len(data)
                if budget is not None:
                    budget -= len(data)
                    if budget < 0:
                        return "real expanded size too large", []
                members.append((info.filename, data))
        return None, members

    # --- main entry ------------------------------------------------------------
    def ingest(self, filename: str, content: bytes, source: str) -> IngestResult:
        digest = hashlib.sha256(content).hexdigest()

        # L3 first: an unknown connector is not allowed to write to the index at all.
        policy = SOURCES.get(source)
        if policy is None:
            return self._decide(filename, digest, "rejected", [f"unknown source '{source}'"])

        error, real_type = self._validate(filename, content)
        if error:
            return self._decide(filename, digest, "rejected", [error])

        if real_type == "zip":
            error, members = self._expand_archive(content)
            if error:
                return self._decide(filename, digest, "rejected", [error])
            results = [self.ingest(name, data, source) for name, data in members]
            statuses = {r.status for r in results}
            status = "indexed" if statuses <= {"indexed"} else "quarantined" if "quarantined" in statuses else "rejected"
            return self._decide(filename, digest, status, [f"{len(members)} members"])

        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return self._decide(filename, digest, "rejected", ["not valid UTF-8"])

        reasons: list[str] = []
        hidden_parts: list[str] = []

        # Front matter is read ONLY to drop it. Its claims are never used (L3).
        if text.startswith("---\n") and "\n---\n" in text[4:]:
            text = text[text.find("\n---\n", 4) + 5:]
            reasons.append("ignored self-declared metadata")

        # L4: sanitize
        if self.strip_hidden:
            if real_type == "html":
                parser = _VisibleTextParser()
                parser.feed(text)
                text, hidden_parts = " ".join(parser.visible), parser.hidden
            else:
                text, hidden_parts = strip_markup_comments(text)
            if any(p.strip() for p in hidden_parts):
                reasons.append("hidden text removed")
        elif real_type == "html":
            text = re.sub(r"<[^>]+>", " ", text)
        if self.normalize:
            text, removed = normalize_unicode(text)
            hidden_parts = [normalize_unicode(p)[0] for p in hidden_parts]
            if removed:
                reasons.append(f"{removed} invisible characters removed")
        text = " ".join(text.split())

        # L5: scan the visible AND the removed text. Hidden instructions = clearly suspicious.
        if self.scan_injection:
            scanned = text + "\n" + "\n".join(hidden_parts)
            if any(p.search(scanned) for p in INJECTION_PATTERNS):
                reasons.append("instruction-like text found")
                self.quarantine.append({"filename": filename, "source": source, "sha256": digest,
                                        "reasons": reasons})
                return self._decide(filename, digest, "quarantined", reasons)

        # L3: untrusted sources wait for a human review before they can be indexed.
        if self.enforce_source_trust and not policy.auto_index:
            reasons.append(f"source '{source}' requires review before indexing")
            self.quarantine.append({"filename": filename, "source": source, "sha256": digest,
                                    "reasons": reasons})
            return self._decide(filename, digest, "quarantined", reasons)

        # L6: redact PII before anything is embedded or indexed.
        if self.redact:
            text, found = redact_pii(text)
            if found:
                reasons.append(f"redacted {len(found)} PII values ({', '.join(sorted(set(found)))})")

        # L7: provenance on every chunk. Trust and tenant come from the connector.
        provenance = {
            "filename": filename,
            "source": source,
            "tenant": policy.tenant,
            "trust": policy.trust,
            "sha256": digest,
            "parser_version": PARSER_VERSION,
            "ingested_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        for i, piece in enumerate(chunk(text)):
            self.chunks.append(Chunk(piece, {**provenance, "chunk": i}))
        return self._decide(filename, digest, "indexed", reasons)
