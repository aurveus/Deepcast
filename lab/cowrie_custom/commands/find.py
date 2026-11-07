# Bounded `find` for the deception lab. Mounted over Cowrie's stock src/cowrie/commands/find.py (see lab/docker-compose.yml).
#
# Why: the stock command walks the fake filesystem recursively on the single thread that serves every SSH connection, and it follows
# symbolic links. The lab's filesystem has link loops, so one `find / -name "*.conf"` visited 300000+ entries in 51 s and still
# going: Cowrie sat at 100% CPU and answered nobody until the container was restarted (found in the 2026-10-25 manual session).
# This version behaves like GNU find without -L: it does not descend into symbolic links (the whole tree is about 29000 entries and
# is walked in well under a second), it works in small chunks on the reactor so other sessions keep being served, it has a hard
# cap on the entries it will visit, and Ctrl+C stops it. Output follows real find: starting points are printed as typed, children
# below them, parents before children.
from __future__ import annotations

import fnmatch
import posixpath

from cowrie.shell.command import HoneyPotCommand

commands = {}

CHUNK = 1500            # entries handled per reactor tick
MAX_ENTRIES = 100000    # hard cap on entries visited by one command

TAKES_ARG = {"-name", "-iname", "-path", "-ipath", "-wholename", "-type", "-maxdepth", "-mindepth", "-mtime", "-atime", "-ctime",
             "-mmin", "-amin", "-cmin", "-size", "-perm", "-user", "-group", "-newer", "-regex", "-iregex", "-uid", "-gid"}


class Command_find(HoneyPotCommand):
    """find [path...] [expression]: -name -iname -path -type -maxdepth -mindepth are honored; other tests are accepted and ignored."""

    def start(self) -> None:
        self.maxdepth = None
        self.mindepth = 0
        self.name = self.iname = self.path_pat = self.ipath_pat = self.type_filter = None
        self.visited = 0
        args = list(self.args)
        idx = 0
        roots = []
        while idx < len(args) and not args[idx].startswith("-") and args[idx] not in ("!", "(", ")"):
            roots.append(args[idx])
            idx += 1
        if not roots:
            roots = ["."]
        while idx < len(args):
            a = args[idx]
            if a in TAKES_ARG:
                if idx + 1 >= len(args):
                    self.errorWrite(f"find: missing argument to `{a}'\n")
                    self.exit(1)
                    return
                val = args[idx + 1]
                idx += 2
                if a == "-name":
                    self.name = val
                elif a == "-iname":
                    self.iname = val.lower()
                elif a in ("-path", "-wholename"):
                    self.path_pat = val
                elif a == "-ipath":
                    self.ipath_pat = val.lower()
                elif a == "-type":
                    if val not in ("f", "d", "l"):
                        self.errorWrite(f"find: Unknown argument to -type: {val}\n")
                        self.exit(1)
                        return
                    self.type_filter = val
                elif a in ("-maxdepth", "-mindepth"):
                    try:
                        n = int(val)
                        if n < 0:
                            raise ValueError
                    except ValueError:
                        self.errorWrite(f"find: Expected a positive decimal integer argument to {a}, but got `{val}'\n")
                        self.exit(1)
                        return
                    if a == "-maxdepth":
                        self.maxdepth = n
                    else:
                        self.mindepth = n
                continue
            if a in ("-print", "-print0", "-ls", "-prune", "-xdev", "-mount", "-depth", "-follow", "!", "-not", "-a", "-and", "-o", "-or", "(", ")"):
                idx += 1
                continue
            if a in ("-exec", "-execdir", "-ok", "-okdir"):
                idx += 1
                while idx < len(args) and args[idx] not in (";", "\\;", "+"):
                    idx += 1
                idx += 1
                continue
            self.errorWrite(f"find: unknown predicate `{a}'\n")
            self.exit(1)
            return

        self.stack = []
        missing = False
        for r in reversed(roots):                   # popped in the order typed
            path = self.fs.resolve_path(r, self.cwd)
            if not self.fs.exists(path):
                self.errorWrite(f"find: '{r}': No such file or directory\n")
                missing = True
                continue
            self.stack.append((path, 0, r))
        self.missing = missing
        self.step()

    def step(self) -> None:
        if self.exited:
            return
        n = 0
        while self.stack and n < CHUNK:
            path, depth, shown = self.stack.pop()
            n += 1
            self.visited += 1
            try:
                islink = self.fs.islink(path)
                isdir = (not islink) and self.fs.isdir(path)
                if depth >= self.mindepth and self._match(path, shown, islink, isdir):
                    self.write(f"{shown}\n")
                if isdir and (self.maxdepth is None or depth < self.maxdepth):
                    entries = [e for e in self.fs.listdir(path) if e not in (".", "..")]
                    base = shown.rstrip("/")
                    for e in reversed(entries):
                        self.stack.append((posixpath.join(path, e), depth + 1, f"{base}/{e}"))
            except Exception:                        # an unreadable entry is skipped, as find does
                continue
        if self.visited >= MAX_ENTRIES:
            self.stack = []
        if self.stack:
            self.callLater(0, self.step)             # give the reactor back: other sessions keep being served
        else:
            self.exit(1 if self.missing else 0)

    def _match(self, path: str, shown: str, islink: bool, isdir: bool) -> bool:
        base = posixpath.basename(shown.rstrip("/")) or shown
        if self.name is not None and not fnmatch.fnmatchcase(base, self.name):
            return False
        if self.iname is not None and not fnmatch.fnmatchcase(base.lower(), self.iname):
            return False
        if self.path_pat is not None and not fnmatch.fnmatchcase(shown, self.path_pat):
            return False
        if self.ipath_pat is not None and not fnmatch.fnmatchcase(shown.lower(), self.ipath_pat):
            return False
        if self.type_filter == "l" and not islink:
            return False
        if self.type_filter == "d" and not isdir:
            return False
        if self.type_filter == "f" and (islink or isdir):
            return False
        return True


commands["find"] = Command_find
commands["/bin/find"] = Command_find
commands["/usr/bin/find"] = Command_find
