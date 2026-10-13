"""Best-effort redaction of structured personal data: cards, SSNs, IBANs, keyword-gated IDs."""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import date
from functools import lru_cache
from typing import Any

from .config import PII_REDACTION_DEFAULT, PII_REDACTION_OFF, PII_REDACTION_STRICT

Span = tuple[int, int, str, str]

_DIGIT_BEFORE = re.compile(r"\d[.\-]?\Z")
_DIGIT_AFTER = re.compile(r"[.\-]?\d")
_ASCII_ALNUM = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)
_GLUED_AFTER = re.compile(r"[A-Za-z0-9]*")
_HEX = re.compile(r"[0-9A-Fa-f]*")
_MIN_GLUED_BLOB = 8
_NON_DIGIT = re.compile(r"\D")
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]")
_TWO_DIGITS = re.compile(r"\d\d")


def _embedded_in_longer_token(text: str, start: int, end: int) -> bool:
    if _DIGIT_BEFORE.search(text, max(0, start - 2), start) or _DIGIT_AFTER.match(
        text, end
    ):
        return True
    begin = start
    while begin > max(0, start - 64) and text[begin - 1] in _ASCII_ALNUM:
        begin -= 1
    glued = text[begin:start] + _GLUED_AFTER.match(text, end, end + 64).group()
    return len(glued) >= _MIN_GLUED_BLOB and (
        _HEX.fullmatch(glued) is not None or any(c.isdigit() for c in glued)
    )


def _ascii_digits(text: str) -> str:
    return "".join(str(int(c)) for c in _NON_DIGIT.sub("", text))


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _known_issuer(digits: str) -> bool:
    n = len(digits)
    if digits[0] == "4":
        return n in (13, 16, 19)
    if 51 <= int(digits[:2]) <= 55 or 2221 <= int(digits[:4]) <= 2720:
        return n == 16
    if digits[:2] in ("34", "37"):
        return n == 15
    if digits[:4] == "6011" or digits[:2] == "65" or 644 <= int(digits[:3]) <= 649:
        return n in (16, 19)
    return False


def valid_credit_card(digits: str) -> bool:
    return 13 <= len(digits) <= 19 and _known_issuer(digits) and luhn_valid(digits)


def valid_ssn(digits: str) -> bool:
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    return (
        area not in ("000", "666")
        and area[0] != "9"
        and group != "00"
        and serial != "0000"
    )


def _kw(*words: str) -> str:
    capitalized = "|".join(w[0].upper() + w[1:] for w in words)
    return rf"(?:(?<![A-Za-z])(?i:{'|'.join(words)})|(?<=[a-z0-9])(?:{capitalized}))"


_NUM_SUFFIX = r"(?:[ _-]?(?i:no\.?|number|num|nbr|id|\#))?s?"
_GAP = (
    r"""[\s"'`:=#|(),\[\]{}*_.-]{0,6}"""
    r"""(?:(?i:is|was|of|no\.?|number|\#)[\s"'`:=#.-]{1,4})?"""
)
_ID_WORDS = (
    "order",
    "invoice",
    "tracking",
    "shipment",
    "sku",
    "part",
    "p/n",
    "pn",
    "serial",
    "item",
    "model",
    "catalog",
    "ticket",
    "case",
    "ref",
    "reference",
    "request",
    "trace",
    "span",
    "event",
    "message",
    "msg",
    "build",
    "job",
    "batch",
    "lot",
    "product",
    "transaction",
    "txn",
)
_ID_LABEL = re.compile(
    _kw(*_ID_WORDS)
    + r"s?(?:[ _-]?(?i:id|no\.?|num|number|nbr|\#|code))?"
    + r"""[\s"'`:=#|(),\[\]{}.-]{0,6}\Z"""
)
_CARD_WORDS = (
    "card",
    "visa",
    "master",
    "amex",
    "discover",
    "cc",
    "pan",
    "payment",
    "credit",
    "debit",
)
_CARD_KW = re.compile(
    r"(?i)card|visa|master|amex|discover|\bcc\b|\bpan\b|payment|credit|debit"
)
_CARD = re.compile(
    r"(?<!\d)\d{4}(?:([ \u00a0-])\d{4}\1\d{4}\1\d{4}(?:\1\d{3})?"
    r"|([ \u00a0-])\d{6}\2\d{5}|\d{9,15})(?!\d)"
)
_LIST_BEFORE = re.compile(r"\d[ ,;]{1,2}\Z")
_LIST_AFTER = re.compile(r"[ ,;]{1,2}\d")
_SSN_DASHED = re.compile(r"(?<![0-9])\d{3}-\d{2}-\d{4}(?![0-9])")
_SSN_KEYWORD = re.compile(
    "(?:"
    + _kw(
        "ssn",
        "social[ _-]?security",
        "taxpayer[ _-]?id(?:entification)?",
        "tax[ _-]?id",
    )
    + r"|(?<![A-Za-z])I?TIN(?![A-Za-z]))"
    + _NUM_SUFFIX
    + _GAP
    + r"(?P<v>\d{3}([ -]?)\d{2}\2\d{4})(?![0-9])"
)
_IBAN_LENGTHS = {
    entry[:2]: int(entry[2:])
    for entry in (
        "AD24 AE23 AL28 AT20 AZ28 BA20 BE16 BG22 BH22 BR29 BY28 CH21 CR22 CY28 CZ24 "
        "DE22 DK18 DO28 EE20 EG29 ES24 FI18 FO18 FR27 GB22 GE22 GI23 GL18 GR27 GT28 "
        "HR21 HU28 IE22 IL23 IQ23 IS26 IT27 JO30 KW30 KZ20 LB28 LC32 LI21 LT20 LU20 "
        "LV21 MC27 MD24 ME22 MK19 MR27 MT31 MU30 NL18 NO15 PK24 PL28 PS29 PT25 QA29 "
        "RO24 RS22 SA24 SC31 SE24 SI19 SK24 SM27 ST25 SV28 TL23 TN24 TR26 UA29 VA22 "
        "VG24 XK20"
    ).split()
}
_IBAN = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Z]{2}\d{2}"
    r"(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,3})?)(?![A-Za-z0-9+/])"
)
_PASSPORT = re.compile(
    _kw("passport")
    + _NUM_SUFFIX
    + _GAP
    + r"(?P<v>(?=[A-Z0-9]{0,8}\d)[A-Z0-9]{6,9})(?![A-Za-z0-9])"
)
_DRIVER_LICENCE = re.compile(
    "(?:"
    + _kw(r"driver'?s?[ _-]?licen[cs]e", r"driving[ _-]?licen[cs]e")
    + r"|(?<![A-Za-z])DLN?(?=[ _-]?(?:\#|No|Number)))"
    + _NUM_SUFFIX
    + _GAP
    + r"(?P<v>(?=[A-Z0-9-]{0,19}\d)[A-Z0-9][A-Z0-9-]{3,18}[A-Z0-9])(?![A-Za-z0-9-])"
)
_MRN = re.compile(
    _kw("mrn", "medical[ _-]?record")
    + _NUM_SUFFIX
    + _GAP
    + r"(?P<v>[A-Z]{0,3}\d{5,10})(?![A-Za-z0-9])"
)
_MONTH = r"(?i:(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*)\.?"
_DATE = (
    r"(?:\d{4}(?P<s1>[-/.])\d{1,2}(?P=s1)\d{1,2}|\d{1,2}(?P<s2>[-/.])\d{1,2}(?P=s2)\d{4}"
    r"|\d{8}"
    rf"|{_MONTH} \d{{1,2}}(?:st|nd|rd|th)?,? \d{{4}}"
    rf"|\d{{1,2}}(?:st|nd|rd|th)?[ -]{_MONTH},?[ -]\d{{4}})"
)
_DATE_ONLY = re.compile(_DATE)
_DOB = re.compile(
    _kw(
        "dob",
        r"d\.o\.b\.?",
        "date[ _-]?of[ _-]?birth",
        "birth[ _-]?date",
        "birthday",
        "born(?: on)?",
    )
    + r"s?"
    + _GAP
    + rf"(?P<v>{_DATE})(?![0-9])"
)
_E164 = re.compile(r"(?<![\w+])\+[1-9]\d{7,14}(?![\w])")
_PHONE_KEYWORD = re.compile(
    _kw("phone", "tel", "telephone", "mobile", "cell", "fax", "sms", "whatsapp")
    + "s?(?![a-z])"
)
_PHONE = re.compile(
    r"(?<![\w+.])(?:(?:\+?1[ .-]?)?(?:\([2-9]\d{2}\) ?|[2-9]\d{2}[ .-])[2-9]\d{2}[ .-]\d{4}"
    r"|[2-9]\d{2}[2-9]\d{6}|\+[1-9][\d ().-]{7,18}\d)(?![\w-])"
)
_KEYED_ID = re.compile(r"(?=[A-Za-z0-9 -]*\d)[A-Za-z0-9][A-Za-z0-9 -]{3,22}[A-Za-z0-9]")
_KEY_WORD = re.compile(r"[a-z0-9]+")
_CAMEL_HUMP = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _year_plausible(value: str) -> bool:
    years = [int(y) for y in re.findall(r"\d{4}", value)]
    if len(value) == 8 and value.isdigit():
        years = [int(value[:4])]
        month, day = int(value[4:6]), int(value[6:])
        if not (1 <= month <= 12 and 1 <= day <= 31):
            return False
    return any(1900 <= y <= date.today().year for y in years)


def _labelled(
    text: str, start: int, width: int, words: tuple[str, ...], label: re.Pattern[str]
) -> bool:
    window = text[max(0, start - width) : start]
    lowered = window.lower()
    return any(w in lowered for w in words) and label.search(window) is not None


def _not_id_label(text: str, start: int) -> bool:
    return not _labelled(text, start, 32, _ID_WORDS, _ID_LABEL)


def _cards(text: str, _lower: str) -> Iterator[Span]:
    for m in _CARD.finditer(text):
        start, end = m.span()
        digits = _ascii_digits(m.group())
        grouped = len(digits) != end - start
        if not valid_credit_card(digits) or _embedded_in_longer_token(text, start, end):
            continue
        if grouped and (
            _LIST_BEFORE.search(text, max(0, start - 3), start)
            or _LIST_AFTER.match(text, end)
        ):
            continue
        keyword = _labelled(text, start, 60, _CARD_WORDS, _CARD_KW)
        if not grouped and len(digits) == 19 and not keyword:
            continue
        if keyword or _not_id_label(text, start):
            yield start, end, "card", digits


def _ssns(text: str, lower: str) -> Iterator[Span]:
    for m in _SSN_DASHED.finditer(text):
        start, end = m.span()
        digits = _ascii_digits(m.group())
        if (
            valid_ssn(digits)
            and not _embedded_in_longer_token(text, start, end)
            and _not_id_label(text, start)
        ):
            yield start, end, "ssn", digits
    if not _mentions(lower, ("ssn", "social", "tax")) and "TIN" not in text:
        return
    for m in _SSN_KEYWORD.finditer(text):
        digits = _ascii_digits(m.group("v"))
        if valid_ssn(digits):
            yield m.start("v"), m.end("v"), "ssn", digits


def iban_valid(compact: str) -> bool:
    if _IBAN_LENGTHS.get(compact[:2]) != len(compact):
        return False
    rotated = compact[4:] + compact[:4]
    return int("".join(str(int(c, 36)) for c in rotated)) % 97 == 1


def _ibans(text: str, _lower: str) -> Iterator[Span]:
    for m in _IBAN.finditer(text):
        raw = m.group()
        for candidate in (raw, raw.rsplit(" ", 1)[0]):
            compact = candidate.replace(" ", "")
            if iban_valid(compact):
                yield m.start(), m.start() + len(candidate), "iban", compact
                break


def _mentions(lower: str, hints: tuple[str, ...]) -> bool:
    return any(hint in lower for hint in hints)


def _keyword_values(
    kind: str, pattern: re.Pattern[str], hints: tuple[str, ...], exact: str = "\0"
) -> Any:
    def find(text: str, lower: str) -> Iterator[Span]:
        if not _mentions(lower, hints) and exact not in text:
            return
        for m in pattern.finditer(text):
            value = m.group("v")
            if kind != "dob" or _year_plausible(value):
                yield m.start("v"), m.end("v"), kind, value.upper()

    return find


def _phones(text: str, lower: str) -> Iterator[Span]:
    if "+" in text:
        for m in _E164.finditer(text):
            yield m.start(), m.end(), "phone", m.group()
    hints = ("phone", "tel", "mobile", "cell", "fax", "sms", "whatsapp")
    if not _mentions(lower, hints):
        return
    for kw in _PHONE_KEYWORD.finditer(text):
        m = _PHONE.search(text, kw.end(), kw.end() + 40)
        if m and 8 <= len(_NON_DIGIT.sub("", m.group())) <= 15:
            yield m.start(), m.end(), "phone", "+" + _NON_DIGIT.sub("", m.group())


_DEFAULT_FINDERS = (
    _cards,
    _ssns,
    _ibans,
    _keyword_values("passport", _PASSPORT, ("passport",)),
    _keyword_values("driver_licence", _DRIVER_LICENCE, ("licen",), "DL"),
    _keyword_values("mrn", _MRN, ("mrn", "medical")),
    _keyword_values("dob", _DOB, ("dob", "d.o.b", "birth", "born")),
)
_FINDERS = {
    PII_REDACTION_OFF: (),
    PII_REDACTION_DEFAULT: _DEFAULT_FINDERS,
    PII_REDACTION_STRICT: _DEFAULT_FINDERS + (_phones,),
}


@lru_cache(maxsize=1024)
def _key_kind(key: str) -> str | None:
    words = _KEY_WORD.findall(_CAMEL_HUMP.sub("_", key).lower())
    joined = "_".join(words)
    found = set(words)
    if "ssn" in found or "itin" in found or words in (["tin"], ["tax", "id"]):
        return "ssn"
    if "social_security" in joined or "taxpayer_id" in joined:
        return "ssn"
    if "passport" in found:
        return "passport"
    if found & {"driver", "drivers", "driving"} and found & {"license", "licence"}:
        return "driver_licence"
    if "mrn" in found or "medical_record" in joined:
        return "mrn"
    if found & {"dob", "birthdate", "birthday"} or "birth" in found:
        return "dob"
    if "pan" in found or "card_number" in joined or "cc_number" in joined:
        return "card"
    if found & {"phone", "mobile", "telephone", "fax"}:
        return "phone"
    return None


def _keyed_value(kind: str, value: str) -> str | None:
    if kind in ("ssn", "card"):
        digits = value.replace(" ", "").replace("-", "")
        if not digits.isdigit():
            return None
        valid = valid_ssn if kind == "ssn" else valid_credit_card
        return digits if valid(digits) else None
    if kind == "dob":
        stripped = value.strip()
        ok = _DATE_ONLY.fullmatch(stripped) and _year_plausible(stripped)
        return stripped.upper() if ok else None
    if kind == "phone":
        digits = _NON_DIGIT.sub("", value)
        return "+" + digits if 7 <= len(digits) <= 15 else None
    stripped = value.strip()
    return stripped.upper() if _KEYED_ID.fullmatch(stripped) else None


class PiiRedactor:
    """Replaces detected values with per-report tokens like `[card-1]`; no secret, so nothing to reverse."""

    def __init__(self, level: str = PII_REDACTION_DEFAULT) -> None:
        self.level = level if level in _FINDERS else PII_REDACTION_DEFAULT
        self._finders = _FINDERS[self.level]
        self._tokens: dict[tuple[str, str], str] = {}
        self._counts: dict[str, int] = {}

    def token(self, kind: str, value: str) -> str:
        key = (kind, value)
        if key not in self._tokens:
            self._counts[kind] = self._counts.get(kind, 0) + 1
            self._tokens[key] = f"[{kind}-{self._counts[kind]}]"
        return self._tokens[key]

    def __call__(self, text: str) -> str:
        if not self._finders or not text or not _TWO_DIGITS.search(text):
            return text
        lower = text.lower()
        spans = [span for find in self._finders for span in find(text, lower)]
        if not spans:
            return text
        spans.sort(key=lambda s: (s[0], -s[1]))
        out, pos = [], 0
        for start, end, kind, value in spans:
            if start < pos:
                continue
            out.append(text[pos:start])
            out.append(self.token(kind, value))
            pos = end
        out.append(text[pos:])
        return "".join(out)

    def _keyed(self, key: str | None, value: Any) -> Any:
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            return value
        kind = _key_kind(key) if key is not None else None
        if kind == "phone" and self.level != PII_REDACTION_STRICT:
            kind = None
        if kind is not None and self._finders:
            normalized = _keyed_value(kind, str(value))
            if normalized is not None:
                return self.token(kind, normalized)
        if isinstance(value, int) and self._finders:
            digits = str(abs(value))
            if len(digits) < 19 and valid_credit_card(digits):
                return self.token("card", digits)
        return value

    def structured(self, root: Any) -> Any:
        """Copy of parsed tool input with values under PII keys, and card-valued JSON numbers, tokenized."""
        if not self._finders:
            return root
        holder = [root]
        stack: list[tuple[Any, Any, str | None]] = [(holder, 0, None)]
        while stack:
            parent, slot, key = stack.pop()
            value = parent[slot]
            if isinstance(value, dict):
                copy = dict(value)
                parent[slot] = copy
                stack.extend(
                    (copy, k, k if isinstance(k, str) else None)
                    for k in reversed(list(copy))
                )
            elif isinstance(value, list):
                items = list(value)
                parent[slot] = items
                stack.extend((items, i, key) for i in reversed(range(len(items))))
            else:
                parent[slot] = self._keyed(key, value)
        return holder[0]
