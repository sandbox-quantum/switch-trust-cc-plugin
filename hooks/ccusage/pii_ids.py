"""Checksum and structure validators for payment cards and national ID numbers."""

from __future__ import annotations

import re
from datetime import date

_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 8, 7, 6, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
NINO = re.compile(
    r"(?!BG|GB|KN|NK|NT|TN|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]"
)
IN_PAN = re.compile(r"[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z]")
_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"
_CF_SHAPE = re.compile(
    r"[A-Z]{6}[\dLMNP-V]{2}[A-EHLMPR-T][\dLMNP-V]{2}[A-Z][\dLMNP-V]{3}[A-Z]"
)
_CF_ODD_VALUES = (1, 0, 5, 7, 9, 13, 15, 17, 19, 21) * 2 + (2, 4, 18, 20, 11, 3)
_CF_ODD_VALUES += (6, 8, 12, 14, 16, 10, 22, 25, 24, 23)
_CF_ODD = {
    c: _CF_ODD_VALUES[i] for i, c in enumerate("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
}
_CF_EVEN = {c: ord(c) - 65 if c.isalpha() else int(c) for c in _CF_ODD}
_NIR = re.compile(r"[1-478]\d{2}(?:0[1-9]|1[0-2]|[2-9]\d)(?:\d{2}|2[AB])\d{8}")
_PESEL_CENTURY = {0: 1900, 20: 2000, 40: 2100, 60: 2200, 80: 1800}


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def verhoeff_valid(digits: str) -> bool:
    check = 0
    for i, ch in enumerate(reversed(digits)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[i % 8][int(ch)]]
    return check == 0


def _real_date(year: int, month: int, day: int) -> bool:
    try:
        return date(year, month, day) <= date.today()
    except ValueError:
        return False


def sin_valid(digits: str) -> bool:
    return len(digits) == 9 and digits[0] not in "08" and luhn_valid(digits)


def aadhaar_valid(digits: str) -> bool:
    return (
        len(digits) == 12
        and digits[0] in "23456789"
        and len(set(digits)) > 2
        and verhoeff_valid(digits)
    )


def nino_valid(compact: str) -> bool:
    return NINO.fullmatch(compact) is not None


def in_pan_valid(compact: str) -> bool:
    return IN_PAN.fullmatch(compact) is not None


def dni_valid(compact: str) -> bool:
    if len(compact) != 9 or not compact[1:8].isdigit():
        return False
    head = compact[0]
    if head in "XYZ":
        head = str("XYZ".index(head))
    elif not head.isdigit():
        return False
    return _DNI_LETTERS[int(head + compact[1:8]) % 23] == compact[8]


def codice_fiscale_valid(compact: str) -> bool:
    if not _CF_SHAPE.fullmatch(compact) or sum(c.isdigit() for c in compact) < 2:
        return False
    total = sum(
        _CF_ODD[c] if i % 2 == 0 else _CF_EVEN[c] for i, c in enumerate(compact[:15])
    )
    return chr(65 + total % 26) == compact[15]


def nir_valid(compact: str) -> bool:
    if not _NIR.fullmatch(compact):
        return False
    body = compact[:13].replace("2A", "19").replace("2B", "18")
    return 97 - int(body) % 97 == int(compact[13:])


def bsn_valid(digits: str) -> bool:
    if len(digits) != 9 or not digits.isdigit() or digits.startswith("00"):
        return False
    total = sum(int(d) * (9 - i) for i, d in enumerate(digits[:8]))
    return (total - int(digits[8])) % 11 == 0


def pesel_valid(digits: str) -> bool:
    if len(digits) != 11 or not digits.isdigit():
        return False
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    check = (10 - sum(int(digits[i]) * w for i, w in enumerate(weights)) % 10) % 10
    month = int(digits[2:4])
    century = _PESEL_CENTURY.get(month // 20 * 20)
    return (
        check == int(digits[10])
        and century is not None
        and _real_date(century + int(digits[:2]), month % 20, int(digits[4:6]))
    )


def be_nn_valid(digits: str) -> bool:
    if len(digits) != 11 or not digits.isdigit():
        return False
    month, day = int(digits[2:4]) % 20, int(digits[4:6])
    if month > 12 or day > 31 or int(digits[2:4]) > 52:
        return False
    check = int(digits[9:])
    return check in (97 - int(digits[:9]) % 97, 97 - int("2" + digits[:9]) % 97)
