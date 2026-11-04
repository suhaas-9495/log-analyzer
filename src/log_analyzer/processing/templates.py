"""Message templating: collapse variable parts so identical errors group together.

``Connection timeout to payment-service after 30000ms`` and
``Connection timeout to payment-service after 29950ms`` share the template
``Connection timeout to payment-service after <*>``. Any token containing a digit
(ids, numbers, durations, hashes, file names) is treated as variable.
"""

from __future__ import annotations

import re

_VARIABLE_TOKEN = re.compile(r"[\w.:/@$#%+-]*\d[\w.:/@$#%+-]*")
_MAX_TEMPLATE_CHARS = 240


def template_of(message: str) -> str:
    return _VARIABLE_TOKEN.sub("<*>", message.strip())[:_MAX_TEMPLATE_CHARS]
