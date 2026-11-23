"""Natural ("VL2 before VL10") ordering, as OPNsense lists interfaces."""

import re

_DIGITS = re.compile(r"\d+")


def natural_key(text):
    """A plain string that sorts like a natural sort: VL01 < VL10 < VL49 < VL100_Parents.

    Each run of digits becomes its length (two digits) followed by the number without leading
    zeros, so shorter numbers sort first and equal lengths compare digit by digit. Letters are
    compared case-insensitively. The result is a string so the database can order by it.
    """

    def number(match):
        digits = match[0].lstrip("0") or "0"
        return f"{len(digits):02d}{digits}"

    return _DIGITS.sub(number, text.casefold())
