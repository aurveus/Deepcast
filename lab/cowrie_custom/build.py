#!/usr/bin/env python3
"""Build the breadcrumbs planted INSIDE the SSH honeypot (Cowrie): what an attacker finds after logging in.

  python lab/cowrie_custom/build.py      (run by lab/up.sh and by the controller before it starts an ssh decoy)

Writes lab/cowrie_custom/out/ (generated, git-ignored):
  fs.pickle       Cowrie's fake filesystem with extra entries added (home dir of the planted account, shell history, ssh folder, arp)
  honeyfs/...     contents of those files and of /etc/hosts
  txtcmds/...     fake output of the `arp` command
The files point at the 'internal servers' (db-prod-01, fs-backup-01), which are the DB and SMB decoys at their FIXED addresses
(controller/allowlist.json pool_slot). The controller spawns them when a foothold is detected, so they are live shortly after.
Cowrie is pointed at out/ with COWRIE_HONEYPOT_CONTENTS_PATH, COWRIE_HONEYPOT_TXTCMDS_PATH and COWRIE_SHELL_FILESYSTEM.
"""
import ipaddress
import json
import pickle
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lived_in  # noqa: E402  (believable static content: staff accounts, logs, backup scripts, exports)
OUT = HERE / "out"
BASE = HERE / "base_fs.pickle"          # Cowrie's bundled filesystem, copied out of the image once
T_DIR, T_FILE = 1, 2
M_DIR_700, M_DIR_755, M_FILE_600, M_FILE_644, M_EXEC = 0o40700, 0o40755, 0o100600, 0o100644, 0o100755


def env():
    out = {}
    p = ROOT / ".env"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def ensure_base():
    if BASE.exists():
        return
    cid = subprocess.run(["docker", "create", "cowrie/cowrie:3.1.2"], capture_output=True, text=True, check=True).stdout.strip()
    try:
        subprocess.run(["docker", "cp", f"{cid}:/cowrie/cowrie-git/src/cowrie/data/fs.pickle", str(BASE)], check=True, capture_output=True)
    finally:
        subprocess.run(["docker", "rm", cid], capture_output=True)


def bundled(relpath):
    """Content of a file from Cowrie's bundled filesystem (what an attacker sees by default), read inside the image."""
    code = ("import sys; sys.path.insert(0, '/cowrie/cowrie-git/src'); from cowrie.shell.honeyfs import read_honeyfs_bytes; "
            f"sys.stdout.write(read_honeyfs_bytes('{relpath}').decode())")
    return subprocess.run(["docker", "run", "--rm", "--entrypoint", "/cowrie/cowrie-env/bin/python3", "cowrie/cowrie:3.1.2", "-c", code],
                          capture_output=True, text=True, check=True).stdout


def find(node, parts):
    for part in parts:
        for ch in node[7]:
            if ch[0] == part:
                node = ch
                break
        else:
            return None
    return node


def add(root, path, ntype, mode, uid=0, gid=0, size=0, age_days=30):
    """Create a directory/file node (and missing parent directories); keep an existing node."""
    parts = [p for p in path.split("/") if p]
    node = root
    for i, part in enumerate(parts):
        nxt = find(node, [part])
        last = i == len(parts) - 1
        if nxt is None:
            t = ntype if last else T_DIR
            nxt = [part, t, uid, gid, size if (last and t == T_FILE) else 4096, mode if last else M_DIR_755,
                   time.time() - age_days * 86400, [], None, None]
            node[7].append(nxt)
        node = nxt
    return node


def build():
    e = env()
    allow = json.loads((ROOT / "controller" / "allowlist.json").read_text(encoding="utf-8"))
    tokens = json.loads((ROOT / "lab" / "lures" / "honeytokens.json").read_text(encoding="utf-8"))["tokens"]
    pool = [str(ipaddress.ip_address(i)) for i in range(int(ipaddress.ip_address(e["DECOY_IP_FIRST"])),
                                                        int(ipaddress.ip_address(e["DECOY_IP_LAST"])) + 1)]
    db_ip, smb_ip = pool[allow["templates"]["db_decoy"]["pool_slot"]], pool[allow["templates"]["smb_decoy"]["pool_slot"]]
    ssh_user = next(t["username"] for t in tokens if t["kind"] == "ssh_credential")
    db_user = next(t["username"] for t in tokens if t["kind"] == "mysql_credential")
    host_ip = e.get("HOST_IP", "10.10.10.1")

    hosts = (f"127.0.0.1\tlocalhost\n127.0.1.1\tsvr04\n{db_ip}\tdb-prod-01 db-prod-01.corp.local\n"
             f"{smb_ip}\tfs-backup-01 fs-backup-01.corp.local\n::1\tlocalhost ip6-localhost ip6-loopback\n")
    history = (f"ls -la /srv/exports/nightly\ncat /etc/hosts\narp -a\nmysql -h db-prod-01 -u {db_user} -p\n"
               f"smbclient -p 4445 //fs-backup-01/DOCS -N\nexit\n")
    known_hosts = f"db-prod-01.corp.local,{db_ip} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq3m0qvM2o0Y1kZc2N7oXw9yT4bq5l1h8dQe6p3fR2u\n"
    arp = (f"db-prod-01.corp.local ({db_ip}) at 00:50:56:aa:bb:21 [ether] on eth0\n"
           f"fs-backup-01.corp.local ({smb_ip}) at 00:50:56:aa:bb:22 [ether] on eth0\n"
           f"_gateway ({host_ip}) at 00:50:56:c0:00:01 [ether] on eth0\n")

    ensure_base()
    fs = pickle.load(open(BASE, "rb"), encoding="utf-8")
    files = {  # path -> (content, mode, uid)
        "/etc/hosts": (hosts, M_FILE_644, 0),
        "/root/.bash_history": (history, M_FILE_600, 0),
        "/root/.ssh/known_hosts": (known_hosts, M_FILE_644, 0),
        f"/home/{ssh_user}/.bash_history": (history, M_FILE_600, 1001),
        f"/home/{ssh_user}/.ssh/known_hosts": (known_hosts, M_FILE_644, 1001),
    }
    # The planted account must exist in passwd/group, otherwise Cowrie gives that login a blank temporary home.
    drop_default = lambda txt: "\n".join(l for l in txt.split("\n") if not l.startswith("phil:"))   # Cowrie's default account is a known honeypot tell
    staff = lived_in.users()
    passwd_extra = "".join(f"{n}:x:{u}:{u}:{c}:/home/{n}:/bin/bash\n" for n, u, c in staff)
    group_extra = "".join(f"{n}:x:{u}:\n" for n, u, _ in staff)
    files["/etc/passwd"] = (drop_default(bundled("etc/passwd")).rstrip("\n") + f"\n{ssh_user}:x:1001:1001:{lived_in.LURE_OWNER_COMMENT}:/home/{ssh_user}:/bin/bash\n" + passwd_extra, M_FILE_644, 0)
    files["/etc/group"] = (drop_default(bundled("etc/group")).rstrip("\n") + f"\n{ssh_user}:x:1001:\n" + group_extra, M_FILE_644, 0)
    ages = {}
    for path, (content, mode, uid, age) in lived_in.files(db_ip, smb_ip, host_ip, ssh_user).items():
        files.setdefault(path, (content, mode, uid))     # the breadcrumbs above win if a path is defined twice
        ages[path] = age
    for path, mode, uid in lived_in.dirs(ssh_user):
        add(fs, path, T_DIR, mode, uid=uid, gid=uid)
    home = find(fs, ["home"])
    if home is not None:
        home[7][:] = [c for c in home[7] if c[0] != "phil"]
    add(fs, f"/home/{ssh_user}", T_DIR, M_DIR_700, uid=1001, gid=1001)
    add(fs, "/root/.ssh", T_DIR, M_DIR_700)
    add(fs, f"/home/{ssh_user}/.ssh", T_DIR, M_DIR_700, uid=1001, gid=1001)
    for path, (content, mode, uid) in files.items():
        node = add(fs, path, T_FILE, mode, uid=uid, gid=uid, size=len(content), age_days=ages.get(path, 30))
        node[4] = len(content)
        dest = OUT / "honeyfs" / path.lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8", newline="\n")
    for cmd in ("/usr/bin/arp", "/usr/sbin/arp"):
        add(fs, cmd, T_FILE, M_EXEC, size=1024)
        dest = OUT / "txtcmds" / cmd.lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(arp, encoding="utf-8", newline="\n")
    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / "fs.pickle", "wb") as f:
        pickle.dump(fs, f, protocol=2)
    print(f"built {OUT.relative_to(ROOT)} (breadcrumbs: db-prod-01={db_ip}, fs-backup-01={smb_ip}, account={ssh_user})")


if __name__ == "__main__":
    build()
