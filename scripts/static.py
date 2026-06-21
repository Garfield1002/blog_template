"""
Static asset handling — file copying, Jinja2 template rendering, and SRI
integrity hashing.

Used by ``publish.py`` during the build.
"""

import base64
import hashlib
import re
import shutil
import sys
from pathlib import Path

import jinja2
import mistune

from lib import BASE_DIR, CSP, OUT_DIR, SRC_DIR

# ---------------------------------------------------------------------------
# Page templates rendered with Jinja2 (relative to SRC_DIR)
# ---------------------------------------------------------------------------
_PAGE_TEMPLATES = [
    "index.html.j2",
    "post/index.html.j2",
    "logout/index.html.j2",
    "unauthorized/index.html.j2",
]


def sri_hash(filepath: Path) -> str:
    """Compute a ``sha256-<base64>`` SRI integrity hash for *filepath*."""
    sha256 = hashlib.sha256(filepath.read_bytes()).digest()
    b64_hash = base64.b64encode(sha256).decode("ascii")
    return f"sha256-{b64_hash}"


def inject_sri(html_path: Path) -> None:
    """Add ``integrity`` attributes to ``<script src>`` and ``<link
    rel=stylesheet>`` tags in *html_path*.

    Resolves each ``src`` / ``href`` relative to the HTML file's directory,
    computes the SHA-256 hash of the referenced file, and injects an
    ``integrity`` attribute.  Tags that already have an integrity attribute
    are left unchanged.
    """
    html = html_path.read_text(encoding="utf-8")
    html_dir = html_path.parent

    def _replace_src(match: re.Match) -> str:
        tag = match.group(0)
        if "integrity=" in tag:
            return tag
        src = match.group(1)
        path = (html_dir / src).resolve()
        if path.exists():
            integrity = sri_hash(path)
            return tag[:-1] + f' integrity="{integrity}">'
        return tag

    # Inject SRI on <script src="..."> tags.
    html = re.sub(
        r'<script\s[^>]*src="([^"]+)"[^>]*>',
        _replace_src,
        html,
    )
    # Inject SRI on <link rel="stylesheet" href="..."> tags.
    html = re.sub(
        r'<link\s[^>]*rel="stylesheet"[^>]*href="([^"]+)"[^>]*>',
        _replace_src,
        html,
    )
    html_path.write_text(html, encoding="utf-8")


# ---------------------------------------------------------------------------
#  Step: copy static assets
# ---------------------------------------------------------------------------


def copy_static_assets(
    src_dir: Path | None = None,
    out_dir: Path | None = None,
) -> None:
    """Copy everything from *src_dir* to *out_dir*, skipping Jinja2 templates
    (``*.j2``) and the per-user template directory (``user/``)."""
    if src_dir is None:
        src_dir = SRC_DIR
    if out_dir is None:
        out_dir = OUT_DIR

    shutil.copytree(
        src_dir,
        out_dir,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("user", "*.j2"),
    )
    print(f"Copied static assets from {src_dir} to {out_dir}")


# ---------------------------------------------------------------------------
#  Step: render Jinja2 templates
# ---------------------------------------------------------------------------


def render_templates(
    src_dir: Path | None = None,
    out_dir: Path | None = None,
    csp: str | None = None,
    base_dir: Path | None = None,
) -> None:
    """Render every Jinja2 page template (login, architecture, index, post,
    logout, unauthorized) and write the resulting ``.html`` files into
    *out_dir*."""
    if src_dir is None:
        src_dir = SRC_DIR
    if out_dir is None:
        out_dir = OUT_DIR
    if csp is None:
        csp = CSP
    if base_dir is None:
        base_dir = BASE_DIR

    markdown = mistune.create_markdown(escape=True)

    jinja_env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(src_dir)),
        autoescape=True,
    )

    # --- /login.html (GitHub Pages compat — fragment-preserving auth) ---
    login_html = jinja_env.get_template("login.html.j2").render(csp=csp)
    (out_dir / "login.html").write_text(login_html, encoding="utf-8")
    print("  Created login.html (GitHub Pages compat)")

    # --- /arch.html (public architecture page) ---
    arch_md = base_dir / "architecture.md"
    if arch_md.exists():
        arch_content = markdown(arch_md.read_text(encoding="utf-8"))
        arch_html = jinja_env.get_template("arch.html.j2").render(
            csp=csp, content=arch_content
        )
        (out_dir / "arch.html").write_text(arch_html, encoding="utf-8")
        print("  Rendered architecture → arch.html")
    else:
        print("  Skipping arch.html (architecture.md not found)")

    # --- Per-page templates ---
    for template_name in _PAGE_TEMPLATES:
        out_path = out_dir / template_name.replace(".j2", "")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        html = jinja_env.get_template(template_name).render(csp=csp)
        out_path.write_text(html, encoding="utf-8")
    print("  Rendered page templates (index, post, logout, unauthorized)")


# ---------------------------------------------------------------------------
#  Step: inject SRI on every HTML file in the output tree
# ---------------------------------------------------------------------------


def inject_sri_all(out_dir: Path | None = None) -> None:
    """Walk *out_dir* and inject SRI integrity hashes into every ``.html``
    file."""
    if out_dir is None:
        out_dir = OUT_DIR

    for html_file in sorted(out_dir.rglob("*.html")):
        inject_sri(html_file)
        print(f"  SRI: {html_file.relative_to(out_dir)}")
