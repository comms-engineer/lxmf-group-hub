"""Public codenames used when a group does not choose an explicit alias."""

from __future__ import annotations

import secrets

PUBLIC_ALIASES = (
    "Arctic Canopy", "Frost Vector", "Static Architect", "Logic Tether",
)

def choose_alias(used: set[str]) -> str:
    """Choose an unused codename, adding a suffix after the pool is exhausted."""
    available = [alias for alias in PUBLIC_ALIASES if alias not in used]
    if available:
        return secrets.choice(available)

    suffix = 2
    while f"{PUBLIC_ALIASES[0]} {suffix}" in used:
        suffix += 1
    return f"{PUBLIC_ALIASES[0]} {suffix}"
