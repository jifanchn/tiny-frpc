#!/usr/bin/env python3
"""
Python bindings smoke/unit tests (cover critical paths as much as possible).

Notes:
- Does NOT require a real FRPS (uses a minimal mock server for Login/LoginResp only).
- Coverage: connect success, auth failure, protocol error, tunnel start/stop, stats, inject Yamux frame -> data_callback.
"""

import json
import socket
import struct
import threading
import time

from frpc_python import FRPCClient, TunnelType, ErrorCode, cleanup


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise RuntimeError("EOF while reading")
        buf += chunk
    return buf


class MockFrps:
    """A minimal FRPS-like server for Login/LoginResp only."""

    def __init__(self, mode: str):
        # mode: "ok" | "auth_fail" | "wrong_type" | "missing_run_id"
        self._mode = mode
        self._stop = threading.Event()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self):
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        self._thread.join(timeout=1.0)

    def _serve(self):
        try:
            conn, _ = self._listener.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(2.0)
            try:
                msg_type = _recv_exact(conn, 1)
                _ = msg_type  # 'o' (Login)
                length_be = _recv_exact(conn, 8)
                length = struct.unpack(">q", length_be)[0]
                if length < 0 or length > 1024 * 1024:
                    return
                _ = _recv_exact(conn, int(length))

                if self._mode == "auth_fail":
                    resp = {"version": "0.62.1", "error": "bad token"}
                    resp_type = b"1"
                elif self._mode == "wrong_type":
                    resp = {"version": "0.62.1", "run_id": "py_test_run_id"}
                    resp_type = b"X"
                elif self._mode == "missing_run_id":
                    resp = {"version": "0.62.1"}
                    resp_type = b"1"
                else:
                    resp = {"version": "0.62.1", "run_id": "py_test_run_id"}
                    resp_type = b"1"

                resp_bytes = json.dumps(resp).encode("utf-8")
                conn.sendall(resp_type + struct.pack(">q", len(resp_bytes)) + resp_bytes)

                # Keep the TCP connection alive for a short time.
                # Current bindings do not read further frames.
                deadline = time.time() + 1.0
                while not self._stop.is_set() and time.time() < deadline:
                    time.sleep(0.01)
            except Exception:
                return


def main() -> int:
    # Positive: connect success + create/start/stop tunnels + send/stats + inject Yamux frame -> data_callback.
    frps_ok = MockFrps("ok")
    try:
        client = FRPCClient("127.0.0.1", frps_ok.port, "test_token")
        client.connect()

        server_tunnel = client.create_tunnel(
            TunnelType.STCP_SERVER,
            "py_stcp_server",
            secret_key="py_secret",
            local_addr="127.0.0.1",
            local_port=8080,
        )
        server_tunnel.start()
        server_tunnel.stop()

        got = {"data": None}

        def on_data(data: bytes):
            got["data"] = data

        visitor_tunnel = client.create_tunnel(
            TunnelType.STCP_VISITOR,
            "py_stcp_visitor",
            secret_key="py_secret",
            remote_name="remote_server",
            bind_addr="127.0.0.1",
            bind_port=9090,
            data_callback=on_data,
        )
        visitor_tunnel.start()
        sent = visitor_tunnel.send_data(b"hello-from-python")
        if sent <= 0:
            raise RuntimeError("expected send_data > 0")

        # Inject a Yamux DATA frame: version=0, type=DATA(0), flags=0, stream_id=1, length=payload
        payload = b"inbound-from-python"
        hdr = bytearray(12)
        hdr[0] = 0  # version
        hdr[1] = 0  # type=DATA
        hdr[2:4] = (0).to_bytes(2, "big")
        hdr[4:8] = (1).to_bytes(4, "big")  # stream_id
        hdr[8:12] = (len(payload)).to_bytes(4, "big")
        frame = bytes(hdr) + payload
        consumed = visitor_tunnel.inject_yamux_frame(frame)
        if consumed <= 0:
            raise RuntimeError("expected inject_yamux_frame > 0")
        if got["data"] != payload:
            raise RuntimeError("expected data_callback to receive injected payload")

        st = visitor_tunnel.get_stats()
        if st.get("bytes_received", 0) <= 0:
            raise RuntimeError("expected bytes_received > 0 after injection")

        visitor_tunnel.stop()

        client.disconnect()
        client.close()
    finally:
        frps_ok.close()

    # Negative: auth failure should surface as ErrorCode.AUTH.
    frps_bad = MockFrps("auth_fail")
    try:
        bad_client = FRPCClient("127.0.0.1", frps_bad.port, "bad_token")
        try:
            bad_client.connect()
            raise RuntimeError("expected connect() to fail with auth error")
        except Exception as e:
            code = getattr(e, "error_code", None)
            if code != ErrorCode.AUTH:
                raise
        finally:
            bad_client.close()
    finally:
        frps_bad.close()

    # Negative: protocol errors (wrong response type / missing run_id) should surface as ErrorCode.PROTO.
    frps_wrong_type = MockFrps("wrong_type")
    try:
        bad_client = FRPCClient("127.0.0.1", frps_wrong_type.port, "test_token")
        try:
            bad_client.connect()
            raise RuntimeError("expected connect() to fail with proto error")
        except Exception as e:
            code = getattr(e, "error_code", None)
            if code != ErrorCode.PROTO:
                raise
        finally:
            bad_client.close()
    finally:
        frps_wrong_type.close()

    frps_missing = MockFrps("missing_run_id")
    try:
        bad_client = FRPCClient("127.0.0.1", frps_missing.port, "test_token")
        try:
            bad_client.connect()
            raise RuntimeError("expected connect() to fail with proto error (missing run_id)")
        except Exception as e:
            code = getattr(e, "error_code", None)
            if code != ErrorCode.PROTO:
                raise
        finally:
            bad_client.close()
    finally:
        frps_missing.close()

    cleanup()
    print("python bindings smoke test: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


