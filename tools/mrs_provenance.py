"""Resolve GitHub Raw MRS inputs to fixed upstream commits."""
import json
import os
import re
import urllib.request
from urllib.parse import quote, urlsplit

_SHA = re.compile(r"^[a-f0-9]{40}$")


def pin_source_url(url, cache=None):
    """Return (immutable raw URL, upstream commit SHA). Fail closed."""
    p = urlsplit(url)
    parts = p.path.lstrip("/").split("/", 3)
    if (p.scheme != "https" or p.netloc != "raw.githubusercontent.com"
            or p.query or p.fragment or len(parts) != 4
            or any(not v for v in parts)):
        raise ValueError("Unsupported MRS source: " + url)
    owner, repo, ref, path = parts
    if (not re.fullmatch(r"[\w.-]+", owner) or
            not re.fullmatch(r"[\w.-]+", repo) or
            not re.fullmatch(r"[\w.-]+", ref) or
            ".." in path.split("/")):
        raise ValueError("Unsafe MRS source: " + url)
    key = (owner, repo, ref)
    if cache is not None and key in cache:
        sha = cache[key]
    else:
        endpoint = f"https://api.github.com/repos/{owner}/{repo}/commits/{quote(ref, safe='')}"
        headers = {"User-Agent": "clash-resources-mrs-provenance",
                   "Accept": "application/vnd.github+json"}
        token = os.environ.get("GH_TOKEN")
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(endpoint, headers=headers)
        with urllib.request.urlopen(request, timeout=40) as response:
            sha = json.load(response).get("sha")
        if not isinstance(sha, str) or not _SHA.fullmatch(sha):
            raise ValueError("GitHub response missing commit SHA: " + url)
        if cache is not None:
            cache[key] = sha
    return (f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/"
            + quote(path, safe="/._-~"), sha)


def snapshot_path(root, name, source_format):
    """Repository-relative path for an unmodified, current upstream input."""
    from pathlib import Path
    extensions = {"text": "txt", "yaml": "yaml", "mrs": "mrs", "json": "json"}
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
        raise ValueError("Unsafe MRS source name: " + name)
    if source_format not in extensions:
        raise ValueError("Unsupported MRS source format: " + source_format)
    return Path(root) / "sources" / "mrs" / f"{name}.{extensions[source_format]}"


def save_source_snapshot(root, name, source_format, raw):
    """Save the exact fetched bytes; unchanged input does not rewrite the file."""
    import hashlib
    from pathlib import Path
    target = snapshot_path(root, name, source_format)
    if target.is_file() and target.read_bytes() == raw:
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    pending = target.with_name(target.name + ".tmp")
    try:
        pending.write_bytes(raw)
        if hashlib.sha256(pending.read_bytes()).digest() != hashlib.sha256(raw).digest():
            raise RuntimeError("MRS snapshot write failed verification")
        pending.replace(target)
    finally:
        pending.unlink(missing_ok=True)
    return target


def verify_source_snapshots(root, entries):
    """Fail if any source bytes differ from the manifest before git commit."""
    import hashlib
    from pathlib import Path
    root = Path(root)
    for entry in entries:
        expected = snapshot_path(root, entry["name"], entry["format"])
        recorded = expected.relative_to(root).as_posix()
        if entry.get("source_snapshot_path") != recorded:
            raise ValueError(f"MRS snapshot path mismatch: {entry['name']}")
        raw = expected.read_bytes()
        actual = hashlib.sha256(raw).hexdigest()
        if actual != entry["source_sha256"] or len(raw) != entry["source_size_bytes"]:
            raise ValueError(f"MRS snapshot hash/size mismatch: {entry['name']}")


def commit_page(url, commit_sha):
    """Explicit upstream GitHub commit link, not a guessed release tag."""
    from urllib.parse import urlsplit
    parts = urlsplit(url).path.lstrip("/").split("/", 3)
    return f"https://github.com/{parts[0]}/{parts[1]}/commit/{commit_sha}"
