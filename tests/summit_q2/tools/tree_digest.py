"""MRH tree digest, reproducing the method behind f509ec55...20e6.

Equivalent to running, from the parent directory `x/`:
    find <tree> -type f | sort | xargs sha256sum | sha256sum
with GNU coreutils on Git for Windows: lines "<sha256> *<tree>/<relpath>\n", sorted by
path case-insensitively. Usage: python -I tree_digest.py <tree dir>
"""
import hashlib
import os
import sys


def tree_digest(root):
    root = os.path.abspath(root)
    name = os.path.basename(root.rstrip("\\/"))
    rows = []
    for dp, _, fns in os.walk(root):
        for fn in fns:
            p = os.path.join(dp, fn)
            rel = name + "/" + os.path.relpath(p, root).replace("\\", "/")
            with open(p, "rb") as fh:
                rows.append((rel, hashlib.sha256(fh.read()).hexdigest()))
    rows.sort(key=lambda r: r[0].lower())
    listing = "".join("%s *%s\n" % (h, r) for r, h in rows)
    return hashlib.sha256(listing.encode("utf-8")).hexdigest(), len(rows), listing


if __name__ == "__main__":
    digest, n, listing = tree_digest(sys.argv[1])
    sys.stdout.write(listing)
    sys.stdout.write("TREE_DIGEST %s files=%d\n" % (digest, n))
