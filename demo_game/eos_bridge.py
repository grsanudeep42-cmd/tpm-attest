"""
eos_bridge.py — calls libeos_sdk.so via ctypes so eac_hook.so intercepts it.
The game imports this module; the LD_PRELOAD hook then fires automatically.
"""
import ctypes, os, socket, json, threading

_LIB_PATH = os.path.join(os.path.dirname(__file__), "..", "phase3", "libeos_sdk.so")
_SOCK_PATH = "/tmp/eac_shim.sock"

try:
    _lib = ctypes.CDLL(os.path.abspath(_LIB_PATH))
    _lib.EOS_AntiCheatClient_BeginSession.argtypes = [ctypes.c_char_p]
    _lib.EOS_AntiCheatClient_BeginSession.restype  = None
    _MSG_CB = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_size_t)
    _lib.EOS_AntiCheatClient_AddNotifyMessageToServer.argtypes = [_MSG_CB]
    _lib.EOS_AntiCheatClient_AddNotifyMessageToServer.restype  = None
    _LOADED = True
except OSError as e:
    print(f"[EOS_BRIDGE] WARNING: could not load libeos_sdk.so: {e}")
    _LOADED = False

_result   = {"done": False, "valid": False, "reason": "not started"}
_cb_ref   = None  # keep alive


def _msg_cb(msg: bytes, length: int):
    pass


def _query_shim_direct() -> dict:
    """Fallback: talk to shim socket directly (no LD_PRELOAD)."""
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(35)
        s.connect(_SOCK_PATH)
        payload = json.dumps({"type": "eac_intercept", "player_id": "demo_player", "original_message": ""})
        s.sendall(payload.encode())
        s.shutdown(socket.SHUT_WR)
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        return json.loads(data.decode())
    except Exception as e:
        return {"valid": False, "reason": str(e)}


def begin_attestation(player_id: str = "demo_player") -> None:
    """Non-blocking: fires EOS calls in a thread, sets _result when done."""
    global _cb_ref

    def _run():
        global _result
        if _LOADED:
            _lib.EOS_AntiCheatClient_BeginSession(player_id.encode())
            cb = _MSG_CB(_msg_cb)
            _cb_ref = cb
            # This call triggers eac_hook.so → shim → TPM → server
            _lib.EOS_AntiCheatClient_AddNotifyMessageToServer(cb)
            # After the hook returns, query the shim directly for the result
        resp = _query_shim_direct()
        _result["valid"]  = resp.get("valid", False)
        _result["reason"] = resp.get("reason", "unknown")
        _result["token"]  = resp.get("token", "")
        _result["done"]   = True

    threading.Thread(target=_run, daemon=True).start()


def get_result() -> dict:
    return _result.copy()
