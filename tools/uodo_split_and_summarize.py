#!/usr/bin/env python
"""Split and summarize UODO decisions from a merged text export.

Input format (observed): multiple decisions concatenated; each decision begins with:
  Warszawa, <day> <polish_month> <year>
  PRAWOMOCNA | NIEPRAWOMOCNA

  Decyzja
  <signature>

Within a decision, page headers exist like: "\fDecyzja <signature>" + "Strona X z Y".

Outputs:
- out/index_all.csv: index of all detected decisions
- out/rodo_violations.md + out/rodo_violations.csv: short summaries for decisions
  that indicate a GDPR/RODO violation.
- Optional: split decisions into files under out/by-year/YYYY/...

Designed to be streaming (no full-file load).
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys
import unicodedata
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Deque, Iterable, Iterator, List, Optional, Tuple


POLISH_MONTHS = {
    "stycznia": 1,
    "lutego": 2,
    "marca": 3,
    "kwietnia": 4,
    "maja": 5,
    "czerwca": 6,
    "lipca": 7,
    "sierpnia": 8,
    "wrze\u015bnia": 9,
    "pa\u017adziernika": 10,
    "listopada": 11,
    "grudnia": 12,
}

DATE_LINE_RE = re.compile(
    r"^\s*(?:\f)?Warszawa,\s*(?P<day>\d{1,2})\s+(?P<month>[A-Za-z\u0104\u0105\u0106\u0107\u0118\u0119\u0141\u0142\u0143\u0144\u00d3\u00f3\u015a\u015b\u0179\u017a\u017b\u017c]+)\s+(?P<year>\d{4})\s*$",
    re.UNICODE,
)
STATUS_RE = re.compile(r"^\s*(PRAWOMOCNA|NIEPRAWOMOCNA)\s*$")
DECYZJA_LINE_RE = re.compile(r"^\s*Decyzja\s*$", re.IGNORECASE)
UZASADNIENIE_RE = re.compile(r"^\s*Uzasadnienie\s*$", re.IGNORECASE)
PAGE_NO_RE = re.compile(r"^\s*Strona\s+\d+\s+z\s+\d+\s*$", re.IGNORECASE | re.UNICODE)
PAGE_DECISION_RE = re.compile(r"^\s*Decyzja\s+\S+\s*$", re.IGNORECASE | re.UNICODE)

URL_RE = re.compile(r"^https?://\S+$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s*$")

GDPR_MENTION_RE = re.compile(
    r"\bRODO\b|rozporz\u0105dzen(?:ia|ie)\s+\(?(UE\)?\s*)?2016/679",
    re.IGNORECASE | re.UNICODE,
)
VIOLATION_VERB_RE = re.compile(
    r"narusze\w+|stwierdza\w*\s+narusze\w+|administracyjn\w*\s+kar\w*\s+pieni\u0119\u017cn\w*|udziela\w*\s+upomnieni\w*",
    re.IGNORECASE | re.UNICODE,
)

ARTICLE_RE = re.compile(
    r"art\.?\s*\d+[a-z]?"  # art. 5a
    r"(?:\s*ust\.?\s*\d+)?"  # ust. 1
    r"(?:\s*pkt\s*\d+)?"  # pkt 2
    r"(?:\s*lit\.?\s*[a-z])?",  # lit. a
    re.IGNORECASE | re.UNICODE,
)

FINE_RE = re.compile(
    r"kar\w*\s+pieni\u0119\u017cn\w*\s+w\s+wysoko\u015bci\s*(?P<amt>[0-9][0-9\s\u00a0\.]*)(?P<cur>z\u0142|zl)",
    re.IGNORECASE | re.UNICODE,
)


@dataclass
class Decision:
    seq: int
    date_iso: Optional[str]
    year: Optional[int]
    status: Optional[str]
    signature: Optional[str]
    text: str


REQUIREMENT_BY_ARTICLE = {
    5: "zasady przetwarzania danych (art. 5 RODO)",
    6: "podstawa prawna przetwarzania (art. 6 RODO)",
    7: "warunki zgody (art. 7 RODO)",
    12: "przejrzysta komunikacja i wykonywanie praw (art. 12 RODO)",
    13: "obowiązek informacyjny przy pozyskiwaniu danych od osoby (art. 13 RODO)",
    14: "obowiązek informacyjny przy pozyskiwaniu danych z innych źródeł (art. 14 RODO)",
    15: "prawo dostępu do danych (art. 15 RODO)",
    16: "prawo do sprostowania (art. 16 RODO)",
    17: "prawo do usunięcia danych (art. 17 RODO)",
    18: "prawo do ograniczenia przetwarzania (art. 18 RODO)",
    20: "prawo do przenoszenia danych (art. 20 RODO)",
    21: "prawo sprzeciwu (art. 21 RODO)",
    22: "zautomatyzowane podejmowanie decyzji / profilowanie (art. 22 RODO)",
    24: "odpowiedzialność administratora (art. 24 RODO)",
    25: "privacy by design/by default (art. 25 RODO)",
    28: "wymogi dot. podmiotu przetwarzającego i umowy powierzenia (art. 28 RODO)",
    30: "rejestr czynności przetwarzania (art. 30 RODO)",
    31: "współpraca z organem nadzorczym (art. 31 RODO)",
    32: "bezpieczeństwo przetwarzania (art. 32 RODO)",
    33: "zgłoszenie naruszenia do UODO (art. 33 RODO)",
    34: "zawiadomienie osób o naruszeniu (art. 34 RODO)",
    35: "ocena skutków dla ochrony danych (DPIA) (art. 35 RODO)",
    37: "wyznaczenie IOD (art. 37 RODO)",
    38: "pozycja IOD (art. 38 RODO)",
    39: "zadania IOD (art. 39 RODO)",
}


def safe_filename_component(value: str, *, max_len: int = 140) -> str:
    value = value.strip()
    if not value:
        return "unknown"

    # Normalize and strip diacritics for filesystem safety (Windows-friendly)
    normalized = unicodedata.normalize("NFKD", value)
    ascii_value = "".join(ch for ch in normalized if not unicodedata.combining(ch))

    # Replace forbidden Windows filename chars
    ascii_value = re.sub(r'[<>:"/\\|?*]', "_", ascii_value)
    ascii_value = re.sub(r"\s+", "_", ascii_value)
    ascii_value = re.sub(r"_+", "_", ascii_value)
    ascii_value = ascii_value.strip("._ ")
    if not ascii_value:
        ascii_value = "unknown"
    return ascii_value[:max_len]


def parse_polish_date(line: str) -> Tuple[Optional[str], Optional[int]]:
    match = DATE_LINE_RE.match(line.replace("\ufeff", ""))
    if not match:
        return None, None
    day = int(match.group("day"))
    month_raw = match.group("month").lower()
    year = int(match.group("year"))

    month = POLISH_MONTHS.get(month_raw)
    if not month:
        return None, year

    try:
        d = date(year, month, day)
        return d.isoformat(), year
    except Exception:
        return None, year


def looks_like_decision_start(date_line: str, lookahead: List[str]) -> Tuple[bool, Optional[str], Optional[str]]:
    """Return (is_start, status, signature) by scanning upcoming lines."""
    # Quick parse date line; must match
    if not DATE_LINE_RE.match(date_line.replace("\ufeff", "")):
        return False, None, None

    nonempty = [ln.strip() for ln in lookahead if ln.strip()]
    # Need status, then "Decyzja", then a signature line
    status: Optional[str] = None
    signature: Optional[str] = None

    # Scan up to first 10 non-empty lines
    for idx, ln in enumerate(nonempty[:12]):
        if status is None and STATUS_RE.match(ln):
            status = ln
            continue
        if status is not None and DECYZJA_LINE_RE.match(ln):
            # signature should be next non-empty
            if idx + 1 < len(nonempty):
                signature = nonempty[idx + 1]
            break

    if status and signature:
        return True, status, signature
    return False, None, None


def iter_decisions(input_path: Path) -> Iterator[Decision]:
    seq = 0
    current_lines: List[str] = []
    current_meta: Tuple[Optional[str], Optional[int], Optional[str], Optional[str]] = (None, None, None, None)

    buffer: Deque[str]
    from collections import deque

    buffer = deque()
    eof = False

    def read_line(f) -> Optional[str]:
        nonlocal eof
        if buffer:
            return buffer.popleft()
        line = f.readline()
        if not line:
            eof = True
            return None
        return line

    def peek_lines(f, n: int) -> List[str]:
        nonlocal eof
        while len(buffer) < n and not eof:
            line = f.readline()
            if not line:
                eof = True
                break
            buffer.append(line)
        return list(buffer)[:n]

    with input_path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        while True:
            line = read_line(f)
            if line is None:
                break

            line_stripped = line.rstrip("\n")

            # Candidate: date line at start of decision
            if DATE_LINE_RE.match(line_stripped.replace("\ufeff", "")):
                lookahead = peek_lines(f, 20)
                ok, status, signature = looks_like_decision_start(line_stripped, lookahead)
                if ok:
                    # New decision starts here
                    if current_lines:
                        seq += 1
                        yield Decision(
                            seq=seq,
                            date_iso=current_meta[0],
                            year=current_meta[1],
                            status=current_meta[2],
                            signature=current_meta[3],
                            text="".join(current_lines),
                        )
                    current_lines = [line]
                    date_iso, year = parse_polish_date(line_stripped)
                    current_meta = (date_iso, year, status, signature)
                    continue

            # Also handle form-feed + Warszawa,
            if line_stripped.startswith("\f") and DATE_LINE_RE.match(line_stripped.replace("\ufeff", "")):
                lookahead = peek_lines(f, 20)
                ok, status, signature = looks_like_decision_start(line_stripped, lookahead)
                if ok:
                    if current_lines:
                        seq += 1
                        yield Decision(
                            seq=seq,
                            date_iso=current_meta[0],
                            year=current_meta[1],
                            status=current_meta[2],
                            signature=current_meta[3],
                            text="".join(current_lines),
                        )
                    current_lines = [line]
                    date_iso, year = parse_polish_date(line_stripped)
                    current_meta = (date_iso, year, status, signature)
                    continue

            current_lines.append(line)

        # Flush last
        if current_lines:
            seq += 1
            yield Decision(
                seq=seq,
                date_iso=current_meta[0],
                year=current_meta[1],
                status=current_meta[2],
                signature=current_meta[3],
                text="".join(current_lines),
            )


def extract_sentencja_text(decision_text: str) -> str:
    lines = decision_text.splitlines()
    out: List[str] = []
    for ln in lines:
        if UZASADNIENIE_RE.match(ln):
            break
        out.append(ln)
    return "\n".join(out)


def normalize_snippet(text: str) -> str:
    # Join line breaks/hyphenations and normalize whitespace for short summaries.
    text = text.replace("\u00ad", "")  # soft hyphen
    text = text.replace("\u2010", "-")
    text = text.replace("\u2011", "-")
    text = text.replace("\u2012", "-")
    text = text.replace("\u2013", "-")
    text = text.replace("\u2014", "-")
    text = re.sub(r"\s+", " ", text, flags=re.UNICODE)
    return text.strip()


GDPR_TITLE_BOILERPLATE_RE = re.compile(
    r"(?i)\b(rozporz\u0105dzen\w*|Rozporz\u0105dzen\w*)\s+Parlamentu\s+Europejskiego\s+i\s+Rady\s*(\(?(UE\)?\s*)?)?2016/679\b[^\.;]{0,350}",
    re.UNICODE,
)


def shorten_violation_text(text: str) -> str:
    """Make a 1-sentence, human-friendly violation snippet.

    Keeps the core clause (e.g. 'naruszenie art. 6 ust. 1 RODO'),
    removes long legal title boilerplate.
    """
    text = normalize_snippet(text)
    if not text:
        return text

    # Remove common GDPR title boilerplate.
    text = GDPR_TITLE_BOILERPLATE_RE.sub("RODO", text)

    # Reduce repeated mentions.
    text = re.sub(r"(?i)\b(UE\s*)?2016/679\b", "RODO", text)
    text = re.sub(r"(?i)\bRozporz\u0105dzen\w*\b", "RODO", text)
    text = re.sub(r"\s+", " ", text).strip()

    # Keep only the first sentence-like chunk.
    for sep in [".", ";"]:
        if sep in text:
            text = text.split(sep, 1)[0]
            break

    # Final cleanup: avoid trailing hyphenated cut-offs.
    text = text.rstrip("- ")
    return text


def extract_violation_clause(decision_text: str) -> Optional[str]:
    sentencja = extract_sentencja_text(decision_text)
    lines = [ln.strip() for ln in sentencja.splitlines()]
    if not lines:
        return None

    def is_candidate(line: str) -> bool:
        low = line.lower()
        if "naruszen" not in low:
            return False
        return (
            "za naruszen" in low
            or "stwierdz" in low
            or "naruszenie art" in low
            or "naruszeniu art" in low
        )

    for i, line in enumerate(lines):
        if not is_candidate(line):
            continue

        chunk_parts: List[str] = [line]
        # Append a few next non-empty lines to complete wrapped sentence.
        for j in range(i + 1, min(len(lines), i + 8)):
            nxt = lines[j]
            if not nxt:
                continue
            chunk_parts.append(nxt)
            joined = " ".join(chunk_parts)
            # stop if it looks like the clause is complete
            if "." in nxt or ";" in nxt:
                break
            if len(joined) >= 420:
                break

        clause = normalize_snippet(" ".join(chunk_parts)).strip(" .;")
        # Make sure we actually captured some article/meaning
        if len(clause) >= 20:
            return clause[:380]

    return None


def parse_article_number(article_token: str) -> Optional[int]:
    m = re.search(r"art\.?\s*(\d+)", article_token, re.IGNORECASE)
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def choose_primary_requirement(text: str, *, clause: Optional[str], articles: List[str]) -> Tuple[Optional[int], Optional[str]]:
    # Prefer article mentioned in the explicit violation clause.
    if clause:
        m = ARTICLE_RE.search(clause)
        if m:
            num = parse_article_number(m.group(0))
            if num and num in REQUIREMENT_BY_ARTICLE:
                return num, REQUIREMENT_BY_ARTICLE[num]

    # Otherwise pick the first meaningful article we extracted.
    for token in articles:
        num = parse_article_number(token)
        if num and num in REQUIREMENT_BY_ARTICLE:
            return num, REQUIREMENT_BY_ARTICLE[num]

    # Last resort: scan whole decision for a common requirement article.
    for m in ARTICLE_RE.finditer(text):
        num = parse_article_number(m.group(0))
        if num and num in REQUIREMENT_BY_ARTICLE:
            return num, REQUIREMENT_BY_ARTICLE[num]
    return None, None


def extract_resolution(sentencja: str) -> Optional[str]:
    raw_lines = [ln.rstrip() for ln in sentencja.splitlines()]

    # Prefer taking the resolution from the part after "po przeprowadzeniu...".
    start_idx = 0
    for i, ln in enumerate(raw_lines):
        if "po przeprowadzeniu" in ln.lower():
            start_idx = i + 1
            break

    lines = [ln.strip() for ln in raw_lines[start_idx:]]

    # remove empty and obvious boilerplate
    filtered: List[str] = []
    for ln in lines:
        if not ln:
            continue
        if URL_RE.match(ln) or TIMESTAMP_RE.match(ln):
            continue
        if PAGE_NO_RE.match(ln):
            continue
        if PAGE_DECISION_RE.match(ln):
            continue
        if ln.lower().startswith("na podstawie"):
            continue
        if ln.lower().startswith("po przeprowadzeniu"):
            continue
        if ln.lower().startswith("warszawa,"):
            continue
        if ln.upper() in {"PRAWOMOCNA", "NIEPRAWOMOCNA"}:
            continue
        if ln.lower() == "decyzja":
            continue
        filtered.append(ln)

    if not filtered and start_idx != 0:
        # Fallback to whole sentencja if we cut away everything
        return extract_resolution("\n".join(raw_lines[:start_idx] + raw_lines[start_idx:]))

    verb_start_re = re.compile(
        r"^(\d+\)|\d+\.|\d+\s*\)|\()?(umarz\w*|odmaw\w*|stwierdz\w*|nak\u0142ad\w*|nakaz\w*|udziel\w*|upomin\w*|zobowi\u0105z\w*|orzek\w*|postanaw\w*)",
        re.IGNORECASE | re.UNICODE,
    )

    # Prefer the last short, verb-starting line.
    for ln in reversed(filtered[-60:]):
        if 3 <= len(ln) <= 260 and verb_start_re.search(ln):
            return ln

    # Fallback: last reasonable line.
    for ln in reversed(filtered[-60:]):
        if 3 <= len(ln) <= 260:
            return ln
    return None


def extract_articles_rodo(text: str) -> List[str]:
    # pick articles that appear near RODO/2016/679
    articles: List[str] = []
    for match in ARTICLE_RE.finditer(text):
        start = match.start()
        end = match.end()
        window = text[end : min(len(text), end + 40)]
        if GDPR_MENTION_RE.search(window):
            normalized = re.sub(r"\s+", "", match.group(0))
            articles.append(normalized)
    # de-dup preserving order
    seen = set()
    uniq: List[str] = []
    for a in articles:
        if a.lower() in seen:
            continue
        seen.add(a.lower())
        uniq.append(a)
    return uniq


def extract_fine(text: str) -> Optional[str]:
    m = FINE_RE.search(text)
    if not m:
        return None
    amt = m.group("amt")
    amt = re.sub(r"\s+|\u00a0", "", amt)
    amt = amt.replace(".", "")
    return f"{amt} zl"


def is_rodo_violation(decision_text: str) -> bool:
    sentencja = extract_sentencja_text(decision_text)
    # Require GDPR mention anywhere, and violation indicators in the "sentencja" (disposition)
    if not GDPR_MENTION_RE.search(decision_text):
        return False
    if VIOLATION_VERB_RE.search(sentencja):
        return True
    # Fallback: if fine is present and GDPR is mentioned
    if extract_fine(sentencja) is not None:
        return True
    return False


def build_summary(dec: Decision) -> str:
    sentencja = extract_sentencja_text(dec.text)
    resolution = extract_resolution(sentencja) or "(brak jednoznacznej sentencji w nag\u0142\u00f3wku)"

    articles = extract_articles_rodo(dec.text)
    fine = extract_fine(dec.text)
    violation_clause = extract_violation_clause(dec.text)
    _req_article, requirement = choose_primary_requirement(dec.text, clause=violation_clause, articles=articles)

    parts = []
    header = []
    if dec.signature:
        header.append(dec.signature)
    if dec.date_iso:
        header.append(dec.date_iso)
    if dec.status:
        header.append(dec.status)
    head = " — ".join(header) if header else f"Decyzja #{dec.seq}"

    parts.append(f"{head}: {normalize_snippet(resolution)}.")
    if violation_clause:
        parts.append(f"Naruszenie: {shorten_violation_text(violation_clause)}.")
    if requirement:
        parts.append(f"Naruszony wym\u00f3g: {requirement}.")
    if fine:
        parts.append(f"Kara: {fine}.")
    if articles:
        # Keep at the end; can be long.
        parts.append(f"Artyku\u0142y RODO (wykryte): {', '.join(articles)}.")
    return " ".join(parts)


def write_text_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", errors="replace")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="Decyzje_UODO_scalone.txt", help="Input merged text file")
    parser.add_argument("--out", default="out", help="Output directory")
    parser.add_argument("--split", action="store_true", help="Write each decision to separate file")
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    index_path = out_dir / "index_all.csv"
    index_enriched_path = out_dir / "index_all_enriched.csv"
    rodo_csv_path = out_dir / "rodo_violations.csv"
    rodo_md_path = out_dir / "rodo_violations.md"

    total = 0
    rodo_total = 0

    with index_path.open("w", encoding="utf-8", newline="") as f_index, index_enriched_path.open(
        "w", encoding="utf-8", newline=""
    ) as f_index_enriched, rodo_csv_path.open("w", encoding="utf-8", newline="") as f_rodo:
        index_writer = csv.DictWriter(
            f_index,
            fieldnames=["seq", "date", "year", "status", "signature", "has_rodo_violation", "file"],
        )
        index_writer.writeheader()

        index_enriched_writer = csv.DictWriter(
            f_index_enriched,
            fieldnames=[
                "seq",
                "date",
                "year",
                "status",
                "signature",
                "has_rodo_violation",
                "resolution",
                "violation",
                "violated_requirement",
                "fine",
                "rodo_articles",
                "file",
            ],
        )
        index_enriched_writer.writeheader()

        rodo_writer = csv.DictWriter(
            f_rodo,
            fieldnames=["seq", "date", "status", "signature", "resolution", "violation", "violated_requirement", "fine", "rodo_articles", "summary"],
        )
        rodo_writer.writeheader()

        rodo_md_lines = ["# Decyzje wskazuj\u0105ce na naruszenie RODO\n"]

        for dec in iter_decisions(input_path):
            total += 1
            has_violation = is_rodo_violation(dec.text)

            sentencja = extract_sentencja_text(dec.text)
            resolution = extract_resolution(sentencja) or ""
            violation_clause = extract_violation_clause(dec.text) or ""
            articles = extract_articles_rodo(dec.text)
            _req_article, requirement = choose_primary_requirement(dec.text, clause=violation_clause or None, articles=articles)
            fine = extract_fine(dec.text) or ""

            out_file_rel: Optional[str] = None
            if args.split:
                year = dec.year or 0
                yyyy = f"{year:04d}" if year else "unknown_year"
                date_part = dec.date_iso or "unknown_date"
                status_part = safe_filename_component(dec.status or "unknown")
                sig_part = safe_filename_component(dec.signature or f"decision_{dec.seq}")
                out_file = out_dir / "by-year" / yyyy / f"{date_part}__{status_part}__{sig_part}.txt"
                write_text_file(out_file, dec.text)
                out_file_rel = str(out_file.relative_to(out_dir)).replace("\\", "/")

            index_writer.writerow(
                {
                    "seq": dec.seq,
                    "date": dec.date_iso or "",
                    "year": dec.year or "",
                    "status": dec.status or "",
                    "signature": dec.signature or "",
                    "has_rodo_violation": "1" if has_violation else "0",
                    "file": out_file_rel or "",
                }
            )

            index_enriched_writer.writerow(
                {
                    "seq": dec.seq,
                    "date": dec.date_iso or "",
                    "year": dec.year or "",
                    "status": dec.status or "",
                    "signature": dec.signature or "",
                    "has_rodo_violation": "1" if has_violation else "0",
                    "resolution": normalize_snippet(resolution) if resolution else "",
                    "violation": shorten_violation_text(violation_clause) if violation_clause else ("" if has_violation else "brak stwierdzenia naruszenia"),
                    "violated_requirement": (requirement or "") if has_violation else "",
                    "fine": fine,
                    "rodo_articles": ";".join(articles),
                    "file": out_file_rel or "",
                }
            )

            if has_violation:
                rodo_total += 1
                summary = build_summary(dec)
                rodo_writer.writerow(
                    {
                        "seq": dec.seq,
                        "date": dec.date_iso or "",
                        "status": dec.status or "",
                        "signature": dec.signature or "",
                        "resolution": normalize_snippet(resolution) if resolution else "",
                        "violation": shorten_violation_text(violation_clause) if violation_clause else "",
                        "violated_requirement": requirement or "",
                        "fine": fine,
                        "rodo_articles": ";".join(articles),
                        "summary": summary,
                    }
                )
                rodo_md_lines.append(f"- {summary}\n")

    rodo_md_path.write_text("".join(rodo_md_lines), encoding="utf-8")

    print(f"Done. Decisions: {total}; RODO violations: {rodo_total}")
    print(f"Index: {index_path}")
    print(f"Enriched index: {index_enriched_path}")
    print(f"RODO summaries: {rodo_md_path}")
    if args.split:
        print(f"Split files under: {out_dir / 'by-year'}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
