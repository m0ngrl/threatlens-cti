"""ThreatLens dashboard - report PDF rendering and indicator highlighting.

The report detail page shows the original PDF under its indicator table, with
every place an indicator appears in the document highlighted. The PDF itself
is never stored in the database - raw_documents.file_path points at it on
disk - so everything here starts from that path.

Pages are rendered to PNG server-side with PyMuPDF (already a core
dependency) rather than shipping a JavaScript PDF viewer, so the dashboard
keeps working offline and needs no frontend build or CDN. Highlights are
returned as rectangles in PDF points; the browser overlays them on the page
images as percentages of the page size, so they line up at any zoom.

Matching is deliberately looser than an exact text search, because an
indicator's stored value often differs from how the PDF prints it:

* long URLs and hashes wrap across lines, so whitespace is ignored;
* reports and extractors defang inconsistently (hxxp, [.], (.), [at] ...),
  so both sides are refanged before comparing;
* registry keys, mutexes etc. vary in case, so comparison is case-folded.

A match must still not be glued to a neighbouring letter or digit, so a
short value like "evil.com" does not light up inside "notevil.com".

PyMuPDF is not thread-safe, and FastAPI runs sync routes in a thread pool
(the page images load in parallel), so every call into it holds _FITZ_LOCK.
"""

from __future__ import annotations

import re
import threading
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import pymupdf

from threatlens.paths import resolve_stored

# Page images are rendered at whatever scale the viewer is displaying them
# (times the screen's pixel ratio), so a page fitted to a large window stays
# sharp. The browser asks in coarse steps so its cache stays useful.
DEFAULT_RENDER_ZOOM = 1.5  # 108 dpi
MIN_RENDER_ZOOM = 0.5
MAX_RENDER_ZOOM = 4.0
MIN_NEEDLE_LENGTH = 3

_FITZ_LOCK = threading.Lock()

# Defang notations seen in CTI reports, mapped to the refanged text. Checked
# in order at each position, so longer patterns come before their prefixes.
_REFANG = (
    ("[://]", "://"),
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    ("(dot)", "."),
    ("[:]", ":"),
    ("[@]", "@"),
    ("[at]", "@"),
    ("(at)", "@"),
    ("hxxp", "http"),
    ("fxp", "ftp"),
)

# Characters that carry no meaning for matching: zero-width spaces, soft
# hyphens, byte-order marks. Real whitespace is handled separately so it can
# still act as a word boundary.
_INVISIBLE = {"\u200b", "\u200c", "\u200d", "\u00ad", "\ufeff"}

# Split ligatures into their letters so "ﬁle" matches "file". Leave image
# blocks out: decoding embedded images made extraction ~70x slower on some
# image-heavy reports, and only text is matched.
_TEXT_FLAGS = pymupdf.TEXTFLAGS_RAWDICT & ~(
    pymupdf.TEXT_PRESERVE_LIGATURES | pymupdf.TEXT_PRESERVE_IMAGES
)


class ReportPdfError(Exception):
    """The report's PDF can't be shown (no file recorded, missing, or unreadable)."""


def resolve_pdf_path(file_path: str | None) -> Path:
    """Turn raw_documents.file_path into an existing PDF on disk.

    Paths are stored relative to the data folder when the file is inside it
    (the repo root in a checkout), absolute otherwise; relative ones are
    resolved against the data folder, not the server's working directory.
    """
    if not file_path:
        raise ReportPdfError("No file is recorded for this report.")

    path = resolve_stored(file_path)
    if not path.is_file():
        raise ReportPdfError(f"The report file is missing from disk: {file_path}")
    if path.suffix.lower() != ".pdf":
        raise ReportPdfError(f"The report file is not a PDF: {path.name}")
    return path


def _fold_char(char: str) -> str:
    """Case-fold and compatibility-normalise one character (ligatures, full-width forms)."""
    return unicodedata.normalize("NFKC", char).casefold()


def _refang(text: str, origins: list[int]) -> tuple[str, list[tuple[int, int]]]:
    """Refang `text`, keeping each output character's source range in `origins`.

    `origins[i]` is the index of whatever `text[i]` came from (a character on
    the page, or a position in a needle). The result maps every refanged
    character to the (first, last) source indices it was produced from.
    """
    out: list[str] = []
    spans: list[tuple[int, int]] = []
    i = 0
    while i < len(text):
        for pattern, replacement in _REFANG:
            if text.startswith(pattern, i):
                span = (origins[i], origins[i + len(pattern) - 1])
                out.extend(replacement)
                spans.extend([span] * len(replacement))
                i += len(pattern)
                break
        else:
            out.append(text[i])
            spans.append((origins[i], origins[i]))
            i += 1
    return "".join(out), spans


def canonical_needle(value: str) -> str:
    """The form an indicator value is searched for in: folded, refanged, no whitespace."""
    folded = "".join(
        _fold_char(char) for char in value if char not in _INVISIBLE and not char.isspace()
    )
    text, _ = _refang(folded, list(range(len(folded))))
    return text


@dataclass
class _PageText:
    """One page's text, folded and refanged, with a way back to character boxes."""

    text: str  # canonical text; single spaces stand in for any whitespace
    spans: list[tuple[int, int]]  # text[i] came from chars[spans[i][0] .. spans[i][1]]
    boxes: list[tuple[float, float, float, float]]  # per page character, rotated page coords
    lines: list[int]  # per page character, which text line it sits on


def _page_text(page: pymupdf.Page) -> _PageText:
    folded: list[str] = []
    origins: list[int] = []
    boxes: list[tuple[float, float, float, float]] = []
    lines: list[int] = []
    rotation = page.rotation_matrix
    line_no = 0

    def add_space() -> None:
        # Whitespace only matters as a word boundary, so runs collapse to one
        # space attributed to the preceding character.
        if folded and folded[-1] != " ":
            folded.append(" ")
            origins.append(len(boxes) - 1)

    for block in page.get_text("rawdict", flags=_TEXT_FLAGS)["blocks"]:
        for line in block.get("lines", ()):
            line_no += 1
            for span in line["spans"]:
                for char in span["chars"]:
                    c = char["c"]
                    if c in _INVISIBLE:
                        continue
                    if c.isspace():
                        add_space()
                        continue
                    rect = pymupdf.Rect(char["bbox"]) * rotation
                    for piece in _fold_char(c):
                        folded.append(piece)
                        origins.append(len(boxes))
                    boxes.append((rect.x0, rect.y0, rect.x1, rect.y1))
                    lines.append(line_no)
            add_space()

    text, spans = _refang("".join(folded), origins)
    return _PageText(text=text, spans=spans, boxes=boxes, lines=lines)


@lru_cache(maxsize=512)
def _needle_pattern(needle: str) -> re.Pattern[str]:
    # Whitespace anywhere inside the value is tolerated (line wraps), but the
    # match must not continue a word on either side.
    body = r"\s?".join(re.escape(char) for char in needle)
    return re.compile(rf"(?<![0-9a-z]){body}(?![0-9a-z])")


def _match_rects(page_text: _PageText, start: int, end: int) -> list[list[float]]:
    """Union the character boxes of text[start:end] into one rectangle per line."""
    first = page_text.spans[start][0]
    last = page_text.spans[end - 1][1]
    per_line: dict[int, list[float]] = {}
    for index in range(first, last + 1):
        x0, y0, x1, y1 = page_text.boxes[index]
        rect = per_line.get(page_text.lines[index])
        if rect is None:
            per_line[page_text.lines[index]] = [x0, y0, x1, y1]
        else:
            rect[0] = min(rect[0], x0)
            rect[1] = min(rect[1], y0)
            rect[2] = max(rect[2], x1)
            rect[3] = max(rect[3], y1)
    return [[round(v, 2) for v in rect] for rect in per_line.values()]


@dataclass(frozen=True)
class Needle:
    indicator_id: int
    values: tuple[str, ...]  # the stored value plus its normalised form


@lru_cache(maxsize=32)
def _find_highlights_cached(
    path: str, mtime_ns: int, needles: tuple[Needle, ...]
) -> dict[str, object]:
    del mtime_ns  # only part of the cache key, so an edited file is re-scanned

    patterns: list[tuple[int, re.Pattern[str]]] = []
    for needle in needles:
        seen: set[str] = set()
        for value in needle.values:
            canonical = canonical_needle(value)
            if len(canonical) >= MIN_NEEDLE_LENGTH and canonical not in seen:
                seen.add(canonical)
                patterns.append((needle.indicator_id, _needle_pattern(canonical)))

    pages: list[dict[str, float]] = []
    matches: list[dict[str, object]] = []
    with _FITZ_LOCK:
        try:
            document = pymupdf.open(path)
        except Exception as exc:  # PyMuPDF raises several unrelated types
            raise ReportPdfError(f"The report file could not be opened: {exc}") from exc
        with document:
            for page_index, page in enumerate(document):
                pages.append({"width": page.rect.width, "height": page.rect.height})
                page_text = _page_text(page)
                claimed: set[tuple[int, int, int]] = set()
                for indicator_id, pattern in patterns:
                    for found in pattern.finditer(page_text.text):
                        # A value and its normalised form can both hit the same text.
                        key = (indicator_id, found.start(), found.end())
                        if key in claimed:
                            continue
                        claimed.add(key)
                        matches.append(
                            {
                                "indicator_id": indicator_id,
                                "page": page_index,
                                "rects": _match_rects(page_text, found.start(), found.end()),
                            }
                        )

    return {"pages": pages, "matches": matches}


def find_highlights(pdf_path: Path, needles: Iterable[Needle]) -> dict[str, object]:
    """Page sizes (in points) and every indicator occurrence as page rectangles.

    Cached per file version and indicator set, since scanning a long report
    takes a few seconds and the page is typically reloaded while reviewing.
    """
    return _find_highlights_cached(
        str(pdf_path), pdf_path.stat().st_mtime_ns, tuple(needles)
    )


def render_page_png(
    pdf_path: Path, page_index: int, zoom: float = DEFAULT_RENDER_ZOOM
) -> bytes:
    zoom = min(max(zoom, MIN_RENDER_ZOOM), MAX_RENDER_ZOOM)
    with _FITZ_LOCK:
        try:
            document = pymupdf.open(pdf_path)
        except Exception as exc:
            raise ReportPdfError(f"The report file could not be opened: {exc}") from exc
        with document:
            if not 0 <= page_index < document.page_count:
                raise IndexError(page_index)
            pixmap = document[page_index].get_pixmap(
                matrix=pymupdf.Matrix(zoom, zoom), alpha=False
            )
            return pixmap.tobytes("png")
