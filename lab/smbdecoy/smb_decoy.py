"""SMB decoy (honeypot) built on Impacket's SimpleSMBServer.
Serves a read-only fake share and writes every Impacket log line as a JSON event."""
import json
import logging
import os
import re
from datetime import datetime, timezone

from impacket import LOG as IMPACKET_LOG
from impacket import smb, smb3structs as smb2, smbserver

LOG_PATH = os.environ.get("SMB_LOG", "/logs/smb.json")
SHARE_NAME = os.environ.get("SMB_SHARE_NAME", "Docs")
SHARE_PATH = "/srv/share"

CONN_RE = re.compile(r"Incoming connection \((?P<ip>[\d.]+),(?P<port>\d+)\)")
AUTH_RE = re.compile(r"AUTHENTICATE_MESSAGE \((?P<domain>[^\\]*)\\(?P<user>[^,]*),(?P<host>[^)]*)\)")


class JsonHandler(logging.Handler):
    def emit(self, record):
        msg = record.getMessage()
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "eventid": "smb.log",
            "message": msg,
        }
        m = CONN_RE.search(msg)
        if m:
            event.update(eventid="smb.connect", src_ip=m["ip"], src_port=int(m["port"]))
        m = AUTH_RE.search(msg)
        if m:
            event.update(eventid="smb.auth", domain=m["domain"], username=m["user"], client_host=m["host"])
        elif "authenticated successfully" in msg or "Authentication failed" in msg:
            event["eventid"] = "smb.auth_result"
        try:
            with open(LOG_PATH, "a") as f:
                f.write(json.dumps(event) + "\n")
        except OSError:
            pass


def log_open(name):
    """Impacket logs only share connects; the file names a client opens are the lure signal (did it read it-notes.txt?)."""
    try:
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps({"timestamp": datetime.now(timezone.utc).isoformat(), "eventid": "smb.open",
                                "message": f"File opened: {name[:200]}", "path": name[:200]}) + "\n")
    except OSError:
        pass


def hook_file_opens(server):
    """Wrap the SMB2 and SMB1 'open file' commands: log the path, then run Impacket's own handler unchanged."""
    srv = server._SimpleSMBServer__server
    orig2 = srv.hookSmb2Command(smb2.SMB2_CREATE, lambda *a: None)

    def create2(connId, smbServer, recvPacket):
        try:
            req = smb2.SMB2Create(recvPacket["Data"])
            log_open(req["Buffer"][:req["NameLength"]].decode("utf-16le"))
        except Exception:
            pass
        return orig2(connId, smbServer, recvPacket)
    srv.hookSmb2Command(smb2.SMB2_CREATE, create2)

    orig1 = srv.hookSmbCommand(smb.SMB.SMB_COM_NT_CREATE_ANDX, lambda *a: None)

    def create1(connId, smbServer, SMBCommand, recvPacket):
        try:
            data = smb.SMBNtCreateAndX_Data(flags=recvPacket["Flags2"], data=SMBCommand["Data"])
            name = data["FileName"]
            log_open(name.decode("utf-16le") if isinstance(name, bytes) else str(name))
        except Exception:
            pass
        return orig1(connId, smbServer, SMBCommand, recvPacket)
    srv.hookSmbCommand(smb.SMB.SMB_COM_NT_CREATE_ANDX, create1)


def main():
    IMPACKET_LOG.addHandler(JsonHandler())
    IMPACKET_LOG.setLevel(logging.INFO)
    server = smbserver.SimpleSMBServer(listenAddress="0.0.0.0", listenPort=445)
    hook_file_opens(server)
    server.addShare(SHARE_NAME.upper(), SHARE_PATH, "Shared documents", readOnly="yes")
    server.setSMB2Support(True)
    server.setSMBChallenge("")  # random challenge per connection
    server.start()


if __name__ == "__main__":
    main()
