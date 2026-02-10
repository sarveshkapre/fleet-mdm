"""Module entrypoint for `python -m fleetmdm`.

Keep this lightweight and defer to the Typer app entrypoint so we stay consistent
with the `fleetmdm` console script.
"""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    main()
