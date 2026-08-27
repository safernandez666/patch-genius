"""Composition of the static pages that carry the side menu.

The frontend has no build step and no template engine, so the menu used to exist
in exactly one file — ``index.html``. Every other screen was a standalone
document with a text link back to the dashboard: no persistent navigation, no
theme toggle, no sign-out, and no way to get from one section to another without
passing through the dashboard first.

Rather than paste the same thirty lines of markup into six files and watch them
drift, the menu lives in ``static/_sidebar.html`` and this module splices it in
where a page writes ``<!--sidebar-->``. A page with no marker comes back
untouched, which is what the sign-in screens want.

Nothing is cached on purpose: these are a few kilobytes read from local disk, and
a cache would mean editing an HTML file and not seeing the change until the
process restarts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

STATIC_DIR = Path("static")
SIDEBAR_MARKER = "<!--sidebar-->"
SIDEBAR_PARTIAL = "_sidebar.html"


def _sidebar(active: Optional[str]) -> str:
    """The menu, with ``active`` marked as the current section.

    Links in the partial carry ``data-nav="/health"`` so the partial itself does
    not need to know which page it is being rendered into.
    """
    html = (STATIC_DIR / SIDEBAR_PARTIAL).read_text(encoding="utf-8")
    if not active:
        return html
    needle = 'data-nav="{}"'.format(active)
    if needle not in html:
        # An unknown section is not worth a 500: the menu renders with nothing
        # highlighted, which is wrong but usable.
        return html
    return html.replace(needle, '{} class="active" aria-current="page"'.format(needle), 1)


def render(page: str, active: Optional[str] = None) -> str:
    """Read ``static/<page>`` and splice the menu into it."""
    html = (STATIC_DIR / page).read_text(encoding="utf-8")
    if SIDEBAR_MARKER not in html:
        return html
    return html.replace(SIDEBAR_MARKER, _sidebar(active), 1)
