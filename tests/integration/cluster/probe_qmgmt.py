"""Submit a job to the pool's schedd through QMGMT, without `condor_submit`.

The queue manager is a second connection: greet the schedd by the sock the
collector published, negotiate a session for `QMGMT_WRITE_CMD` (1112), then send
commands as messages and read a return value back for each.

Opcodes are `qmgmt_constants.h`: 10001 initialize, 10002 new cluster, 10006 set
attribute, 10007 commit. `SetAttribute` takes cluster, proc, value, name - and a
cluster-level attribute uses proc -1.
"""

from __future__ import annotations

import socket
import sys

from xrdhtcondor import cedar, collector

QMGMT_WRITE_CMD = 1112
INITIALIZE = 10001
NEW_CLUSTER = 10002
SET_ATTRIBUTE = 10006
COMMIT = 10007

#: A vanilla job that needs no files of its own, so the pool can run it.
JOB = {
    "JobUniverse": "5",
    "Cmd": '"/bin/echo"',
    "Args": '"qmgmt-put-it-there"',
    "Owner": '"condor"',
    "Iwd": '"/var/lib/condor/execute"',
    "Out": '"qmgmt.out"',
    "Err": '"qmgmt.err"',
    "Requirements": "TRUE",
    "JobStatus": "1",
}


def string(text: str) -> bytes:
    """`code(char*)`: the bytes and a NUL."""
    return text.encode() + b"\x00"


def read_frame(conn: socket.socket) -> bytes | None:
    """One CEDAR message: the five-byte header, then its payload."""
    header = b""
    while len(header) < 5:
        chunk = conn.recv(5 - len(header))
        if not chunk:
            return None
        header += chunk
    size = int.from_bytes(header[1:5], "big")
    payload = b""
    while len(payload) < size:
        chunk = conn.recv(size - len(payload))
        if not chunk:
            return None
        payload += chunk
    return header + payload


def read_return(conn: socket.socket) -> int | None:
    """One reply: `code(int rval)`, and `code(int terrno)` when it failed."""
    frame = read_frame(conn)
    if frame is None:
        return None
    payload = frame[5:]
    print(f"    reply frame {len(payload)} bytes: {payload[:24].hex()}")
    if len(payload) == 8:
        return int.from_bytes(payload[4:8], "big", signed=True)
    return None


def main() -> int:
    host, port, sock = collector.schedd_address("cm")
    print(f"schedd {host}:{port} sock={sock}")

    with socket.create_connection((host, port), timeout=30) as conn:
        conn.settimeout(15)
        conn.sendall(cedar.greeting(sock))
        request = cedar.SecurityRequest(
            auth_methods="CLAIMTOBE",
            encryption="OPTIONAL",
            integrity="OPTIONAL",
            authentication="REQUIRED",
            command=QMGMT_WRITE_CMD,
            subsystem="SUBMIT",
            connect_sinful=f"<{host}:{port}?sock={sock}>",
        )
        conn.sendall(cedar.frame(cedar.security_message(request.as_classads())))
        negotiated = read_frame(conn)
        print(f"  negotiation: {len(negotiated or b'')} bytes")

        # CLAIMTOBE: the client then says who it is, as the capture shows.
        conn.sendall(cedar.frame(cedar.code_int(1) + b"root\x00"))
        named = read_frame(conn)
        print(f"  identity:    {len(named or b'')} bytes {named!r}")

        conn.sendall(cedar.frame(cedar.code_int(INITIALIZE)))
        print(f"  initialize:  {read_return(conn)!r}")

        conn.sendall(cedar.frame(cedar.code_int(NEW_CLUSTER)))
        cluster = read_return(conn)
        print(f"  new cluster: {cluster!r}")
        if cluster is None or cluster < 0:
            print("  FAILED: the queue manager would not open a cluster")
            return 1

        for name, value in JOB.items():
            message = (
                cedar.code_int(SET_ATTRIBUTE)
                + cedar.code_int(cluster)
                + cedar.code_int(-1)
                + string(value)
                + string(name)
            )
            conn.sendall(cedar.frame(message))
            result = read_return(conn)
            if result != 0:
                print(f"  FAILED setting {name}: {result!r}")
                return 1
        print(f"  set {len(JOB)} attributes")

        conn.sendall(cedar.frame(cedar.code_int(COMMIT)))
        committed = read_return(conn)
        print(f"  commit:      {committed!r}")
        if committed != 0:
            print("  FAILED: the transaction was not committed")
            return 1

    print(f"OK: cluster {cluster} submitted by our own QMGMT messages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
