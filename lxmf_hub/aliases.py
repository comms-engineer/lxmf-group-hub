"""Public codenames used when a group does not choose an explicit alias."""

from __future__ import annotations

import secrets


PUBLIC_ALIASES = (
    "Arctic Canopy", "Frost Vector", "Static Architect", "Logic Tether", 
    "Cobalt Quarry", "Neptune Pivot", "Blind Matrix", "Silent Cascade", 
    "Obsidian Orbit", "Paper Eclipse", "Titan Rain", "Copper Gravity", 
    "Echo Lantern", "Mirage Orbit", "Garnet Cipher", "Signal Cavern", 
    "Bronze Tether", "Chalk Harvest", "Radial Reckoning", "Neon Horizon", 
    "Velvet Spectrum", "Void Drifter", "Coronet Falcon", "Sable Monarch", 
    "Burlap Spectrum", "Dark Canopy", "Pulse Sentry", "Copper Obsidian", 
    "Shadow Apex", "Ghost Cavern", "Absolute Mirage", "Hollow Compass", 
    "Project Zenith", "Pinch Vector", "Amber Ripple", "Direct Shadow", 
    "Steel Barricade", "Valiant Beacon", "Burlap Horizon", "Spectrum Tempest", 
    "Swift Crossfire", "Circuit Citadel", "Silver Weaver", "Iron Drift", 
    "Emerald Crown", "Iron Gravity", "Midnight Tension", "Rapid Omen", 
    "Amber Paradox", "Glass Meridian", "Direct Omen", "Crystal Monument", 
    "Titan Nightshade", "Swift Phantom", "Ghost Weaver", "Emerald Forge", 
    "Signal Monarch", "Pulse Quarry", "Obsidian Paradox", "Static Harbor", 
    "Midnight Concord", "Silver Monarch", "Arctic Ripple", "Coronet Pivot", 
    "Circuit Haven", "Echo Ridge", "Crystal Drift", "Zero Monolith", 
    "Shadow Meridian", "Paper Harvest", "Binary Crown", "Logic Vanguard", 
    "Bronze Forge", "Silent Lantern", "Valiant Rain", "Cobalt Tempest", 
    "Radial Fracture", "Absolute Quicksand", "Dark Reckoning", "Frost Citadel", 
    "Mirage Vector", "Steel Concord", "Neptune Firestorm", "Rapid Stonewall", 
    "Looming Anchor", "Vortex Talon", "Pinnacle Lattice", "Kestrel Nomad", 
    "Astral Ridge", "Aether Citadel", "Prism Catalyst", "Sentry Falcon", 
    "Gridline Nomad", "Ember Vector", "Warden Horizon", "Shadow Spire", 
    "Mantra Lattice", "Starlight Foundry", "Zenith Paradigm",
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