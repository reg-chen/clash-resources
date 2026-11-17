#!/usr/bin/env python3
"""Bundle notices from exactly installed Windows build-time distributions."""
from __future__ import annotations
import importlib.metadata as metadata
import re
import sys
from pathlib import Path
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOTS = ("customtkinter", "Pillow", "cryptography", "PyInstaller")
REQUIRE_TEXT = {"customtkinter", "pillow", "cryptography"}
OUTPUT = Path(__file__).resolve().parent / "EXE_THIRD_PARTY_LICENSES.generated.txt"
INTRO = """VPN / Mihomo Generator — 第三方授權聲明

本應用程式使用第三方 Python 套件、Python／Tcl/Tk runtime，
其著作權及授權條款分別歸屬原權利人。
以下名稱、版本及授權原文依本次建置環境所安裝的套件產生。
對品牌名稱的提及不代表廠商贊助、背書或授權使用其商標圖示。

來源及其他第三方素材：
https://github.com/reg-chen/clash-resources/blob/main/docs/THIRD_PARTY_NOTICES.md
"""


def enumerate_dists():
    queue = list(ROOTS)
    seen = set()
    while queue:
        name = queue.pop()
        normalized = canonicalize_name(name)
        if normalized in seen:
            continue
        seen.add(normalized)
        dist = metadata.distribution(name)
        yield dist
        for dependency in dist.requires or ():
            requirement = Requirement(dependency)
            if requirement.marker and not requirement.marker.evaluate({"extra": ""}):
                continue
            queue.append(requirement.name)


def find_license_files(dist):
    records = []
    contents_seen = set()
    for item in dist.files or []:
        filename = str(item).replace("\\", "/")
        leaf = filename.rsplit("/", 1)[-1]
        if not re.match(r"^(LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT)(?:[._ -].*)?$",
                        leaf, flags=re.IGNORECASE):
            continue
        if ".dist-info/" not in filename and ".egg-info/" not in filename:
            continue
        try:
            path = Path(dist.locate_file(item))
            if not path.is_file() or path.stat().st_size > 150000:
                continue
            content = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if content and content not in contents_seen:
            records.append((filename, content))
            contents_seen.add(content)
    return records


def build():
    out = [INTRO]
    for dist in sorted(enumerate_dists(), key=lambda d: canonicalize_name(d.metadata["Name"])):
        name = dist.metadata["Name"]
        found = find_license_files(dist)
        if canonicalize_name(name) in REQUIRE_TEXT and not found:
            raise RuntimeError("Missing license text from " + name + " " + dist.version)
        license_label = dist.metadata.get("License-Expression") or dist.metadata.get("License") or "See upstream license"
        out.append("\n" + "=" * 70 + f"\n{name} {dist.version}\nLicense: {license_label}\n")
        if not found:
            out.append("Distribution metadata lacks a license file: verify upstream separately.\n")
        for filename, content in found:
            out.append(f"\n--- {filename} ---\n{content}\n")
    python_license = Path(sys.base_prefix) / "LICENSE.txt"
    if python_license.is_file():
        out.append("\n" + "=" * 70 + "\nPython runtime license\n")
        out.append(python_license.read_text(encoding="utf-8", errors="replace"))
    else:
        out.append("\nPython runtime license: https://docs.python.org/3/license.html\n")
    for name in ("tcl8.6", "tk8.6", "tcl9.0", "tk9.0"):
        license_path = Path(sys.base_prefix) / "tcl" / name / "license.terms"
        if license_path.is_file():
            out.append("\n" + "=" * 70 + f"\n{name} license.terms\n")
            out.append(license_path.read_text(encoding="utf-8", errors="replace"))
    out.append("\nTcl/Tk license reference: https://www.tcl-lang.org/software/tcltk/license.html\n")
    OUTPUT.write_text("\n".join(out), encoding="utf-8")
    print(f"Generated {OUTPUT.name}: {OUTPUT.stat().st_size} bytes")


if __name__ == "__main__":
    build()
