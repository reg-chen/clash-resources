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
