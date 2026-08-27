"""Unit tests for the side-menu composition."""

from __future__ import annotations

import pytest

from app.pages import SIDEBAR_MARKER, render

# Every screen that carries the menu, with the section it should highlight.
WITH_SIDEBAR = [
    ("index.html", "/"),
    ("brief.html", "/brief"),
    ("health.html", "/health"),
    ("config.html", "/config"),
    ("integraciones.html", "/integraciones"),
    ("ayuda.html", "/ayuda"),
]

ACTIVE = 'class="active" aria-current="page"'


@pytest.mark.parametrize("page,active", WITH_SIDEBAR)
def test_marker_is_replaced_by_the_menu(page, active):
    html = render(page, active=active)
    assert SIDEBAR_MARKER not in html
    assert '<aside class="sidebar">' in html


@pytest.mark.parametrize("page,active", WITH_SIDEBAR)
def test_exactly_one_section_is_marked_current(page, active):
    # Two highlighted links read as two current sections; none reads as a menu
    # that does not know where you are.
    assert render(page, active=active).count(ACTIVE) == 1


@pytest.mark.parametrize("page,active", WITH_SIDEBAR)
def test_the_marked_link_is_the_requested_one(page, active):
    html = render(page, active=active)
    assert 'data-nav="{}" {}'.format(active, ACTIVE) in html


def test_the_partial_carries_no_nested_html_comment():
    # An HTML comment cannot contain another one: a nested `-->` closes the
    # outer comment early and the rest leaks into the page as text.
    html = render("index.html", active="/")
    assert html.count("<!--") == html.count("-->")


def test_an_unknown_section_still_renders_the_menu():
    html = render("index.html", active="/nope")
    assert '<aside class="sidebar">' in html
    assert ACTIVE not in html


def test_a_page_without_the_marker_is_returned_untouched():
    # The sign-in screens deliberately have no menu.
    assert "sidebar" not in render("login.html")
