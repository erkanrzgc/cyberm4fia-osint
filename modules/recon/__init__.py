"""Red team recon package — corporate attack-surface enumeration.

Modules here extend the person-centric OSINT pipeline with
organization-level recon: employee email patterns, GitHub org
commit-author leak, extra subdomain sources.

Each module sticks to the same shape used by ``modules.passive``: async
functions taking ``HTTPClient`` where HTTP is needed, pure helpers where
not, and frozen dataclasses for outputs.
"""
