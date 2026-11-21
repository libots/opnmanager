"""{% icon "fire" %}: inline a vendored Font Awesome Free SVG (CC BY 4.0, see THIRD_PARTY.md)."""

from functools import cache

from django import template
from django.contrib.staticfiles import finders
from django.utils.safestring import mark_safe

register = template.Library()


@cache
def _svg(name):
    path = finders.find(f"icons/{name}.svg")
    if not path:
        raise template.TemplateSyntaxError(f"Unknown icon {name!r}; add it to static/icons/.")
    with open(path, encoding="utf-8") as handle:
        return handle.read().strip()


@register.simple_tag
def icon(name, css_class=""):
    attrs = f'class="{("icon " + css_class).strip()}" aria-hidden="true" focusable="false"'
    return mark_safe(_svg(name).replace("<svg ", f"<svg {attrs} ", 1))
