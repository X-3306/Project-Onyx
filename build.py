#!/usr/bin/env python3
"""Build helper for Project Onyx. / Author: X-3306

The generated ONNX file is a real, tiny neural-network bait graph plus a
metadata vault. The host reads the metadata, derives keys from the local
fingerprint, verifies HMACs in constant time, unlocks the protected key
material, and then uses that key material to decrypt the WebAssembly asset.

Generated private artifacts for example:
  assets/model.onnx
  assets/license_module.wasm.aes
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import hmac
import re
import secrets
import sys
from pathlib import Path
from typing import Optional

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

if sys.platform == "win32":
    from ctypes import wintypes


SCHEMA = "onyx-v1"
MAGIC = b"ONX1"
SALT_LEN = 32
IV_LEN = 16
DEFAULT_KDF_ITERATIONS = 200_000

VAULT_ENC_INFO = b"onyx-vault-enc-v1"
VAULT_MAC_INFO = b"onyx-vault-mac-v1"
TRIGGER_MAC_INFO = b"onyx-trigger-hmac-v1"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
KEY_RE = re.compile(r"^[A-Za-z0-9_+\-/=]{32}$")


def require_trigger(value: str) -> str:
    trigger = value.strip().lower()
    if not SHA256_RE.fullmatch(trigger):
        raise ValueError("trigger must be exactly 64 lowercase hexadecimal characters")
    return trigger


def require_key_material(value: str) -> str:
    key = value.strip()
    if not KEY_RE.fullmatch(key):
        raise ValueError("secret must be exactly 32 chars from A-Z, a-z, 0-9, _, +, -, /, =")
    return key


def _win32_last_error(prefix: str) -> OSError:
    return ctypes.WinError(ctypes.get_last_error(), prefix)


def read_windows_machine_guid() -> str:
    if sys.platform != "win32":
        raise RuntimeError("fingerprint command is only supported on Windows")

    import winreg

    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Cryptography",
        0,
        winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
    ) as key:
        value, _ = winreg.QueryValueEx(key, "MachineGuid")
        return str(value)


def read_windows_volume_serial() -> str:
    if sys.platform != "win32":
        raise RuntimeError("fingerprint command is only supported on Windows")

    serial = wintypes.DWORD()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ok = kernel32.GetVolumeInformationW(
        "C:\\",
        None,
        0,
        ctypes.byref(serial),
        None,
        None,
        None,
        0,
    )
    if not ok:
        raise _win32_last_error("GetVolumeInformationW")
    return f"{serial.value:08X}"


def read_windows_current_user_sid() -> str:
    if sys.platform != "win32":
        raise RuntimeError("fingerprint command is only supported on Windows")

    TOKEN_QUERY = 0x0008
    TOKEN_USER = 1
    ERROR_INSUFFICIENT_BUFFER = 122

    class SidAndAttributes(ctypes.Structure):
        _fields_ = [
            ("Sid", wintypes.LPVOID),
            ("Attributes", wintypes.DWORD),
        ]

    class TokenUser(ctypes.Structure):
        _fields_ = [("User", SidAndAttributes)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        TOKEN_QUERY,
        ctypes.byref(token),
    ):
        return "NO_TOKEN_ACCESS"

    try:
        size = wintypes.DWORD()
        advapi32.GetTokenInformation(token, TOKEN_USER, None, 0, ctypes.byref(size))
        if ctypes.get_last_error() != ERROR_INSUFFICIENT_BUFFER or size.value == 0:
            return "TOKEN_USER_UNREADABLE"

        buffer = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(
            token,
            TOKEN_USER,
            buffer,
            size,
            ctypes.byref(size),
        ):
            return "TOKEN_USER_UNREADABLE"

        token_user = ctypes.cast(buffer, ctypes.POINTER(TokenUser)).contents
        sid_text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(
            token_user.User.Sid,
            ctypes.byref(sid_text),
        ):
            return "SID_CONVERT_FAILED"

        try:
            return sid_text.value
        finally:
            if sid_text:
                kernel32.LocalFree(sid_text)
    finally:
        kernel32.CloseHandle(token)


def compute_windows_fingerprint() -> tuple[str, str]:
    combined = (
        f"MG:{read_windows_machine_guid()}"
        f"|VS:{read_windows_volume_serial()}"
        f"|US:{read_windows_current_user_sid()}"
    )
    return combined, hashlib.sha256(combined.encode("utf-8")).hexdigest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def pbkdf2(trigger_hex: str, salt: bytes, iterations: int) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    ).derive(trigger_hex.encode("ascii"))


def hkdf_expand(master: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
        backend=default_backend(),
    ).derive(master)


def derive_keys(trigger_hex: str, salt: bytes, iterations: int) -> tuple[bytes, bytes, bytes]:
    master = pbkdf2(trigger_hex, salt, iterations)
    return (
        hkdf_expand(master, VAULT_ENC_INFO),
        hkdf_expand(master, VAULT_MAC_INFO),
        hkdf_expand(master, TRIGGER_MAC_INFO),
    )


def mac(key: bytes, data: bytes) -> bytes:
    h = crypto_hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()


def aes_cbc_encrypt_raw(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    iv = secrets.token_bytes(IV_LEN)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    return iv, enc.update(padded) + enc.finalize()


def aes_cbc_decrypt_raw(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def create_tiny_bait_model() -> onnx.ModelProto:
    """Create a small deterministic MLP-like ONNX graph.

    The graph is intentionally useful as a real ONNX Runtime bait workload but
    is not responsible for releasing key material. The protected material is in
    authenticated metadata.
    """
    rng = np.random.default_rng(0x0A11CE)
    w1 = rng.normal(0.0, 0.05, size=(16, 8)).astype(np.float32)
    b1 = rng.normal(0.0, 0.01, size=(8,)).astype(np.float32)
    w2 = rng.normal(0.0, 0.05, size=(8, 4)).astype(np.float32)
    b2 = rng.normal(0.0, 0.01, size=(4,)).astype(np.float32)

    inputs = [
        helper.make_tensor_value_info("input_ids", TensorProto.INT64, [1, 16]),
        helper.make_tensor_value_info("attention_mask", TensorProto.INT64, [1, 16]),
    ]
    outputs = [helper.make_tensor_value_info("logits", TensorProto.FLOAT, [1, 4])]
    initializers = [
        numpy_helper.from_array(w1, "w1"),
        numpy_helper.from_array(b1, "b1"),
        numpy_helper.from_array(w2, "w2"),
        numpy_helper.from_array(b2, "b2"),
    ]
    nodes = [
        helper.make_node("Cast", ["input_ids"], ["ids_f"], to=TensorProto.FLOAT),
        helper.make_node("Cast", ["attention_mask"], ["mask_f"], to=TensorProto.FLOAT),
        helper.make_node("Mul", ["ids_f", "mask_f"], ["masked"]),
        helper.make_node("MatMul", ["masked", "w1"], ["hidden_mm"]),
        helper.make_node("Add", ["hidden_mm", "b1"], ["hidden_pre"]),
        helper.make_node("Relu", ["hidden_pre"], ["hidden"]),
        helper.make_node("MatMul", ["hidden", "w2"], ["out_mm"]),
        helper.make_node("Add", ["out_mm", "b2"], ["out_pre"]),
        helper.make_node("Softmax", ["out_pre"], ["logits"], axis=1),
    ]
    graph = helper.make_graph(nodes, "OnyxBaitModel", inputs, outputs, initializers)
    model = helper.make_model(
        graph,
        producer_name="Project Onyx",
        opset_imports=[helper.make_opsetid("", 17)],
    )
    model.ir_version = 9
    onnx.checker.check_model(model)
    return model


def set_meta(model: onnx.ModelProto, key: str, value: str) -> None:
    entry = model.metadata_props.add()
    entry.key = key
    entry.value = value


def embed_vault(model: onnx.ModelProto, trigger_hex: str, secret: str, iterations: int) -> None:
    salt = secrets.token_bytes(SALT_LEN)
    vault_key, vault_mac_key, trigger_mac_key = derive_keys(trigger_hex, salt, iterations)

    trigger_hmac = mac(trigger_mac_key, trigger_hex.encode("ascii"))
    iv, ciphertext = aes_cbc_encrypt_raw(vault_key, MAGIC + secret.encode("utf-8"))
    ciphertext_hmac = mac(vault_mac_key, ciphertext)

    set_meta(model, "schema", SCHEMA)
    set_meta(model, "kdf", "pbkdf2-hmac-sha256")
    set_meta(model, "kdf_iterations", str(iterations))
    set_meta(model, "kdf_salt", b64(salt))
    set_meta(model, "trigger_hmac", trigger_hmac.hex())
    set_meta(model, "vault_iv", b64(iv))
    set_meta(model, "vault_ct", b64(ciphertext))
    set_meta(model, "vault_hmac", ciphertext_hmac.hex())


def unlock_secret(trigger_hex: str, onnx_path: Path) -> Optional[str]:
    model = onnx.load(str(onnx_path))
    meta = {entry.key: entry.value for entry in model.metadata_props}

    if meta.get("schema") != SCHEMA:
        raise ValueError(f"unsupported schema: {meta.get('schema')}")
    if meta.get("kdf") != "pbkdf2-hmac-sha256":
        raise ValueError(f"unsupported kdf: {meta.get('kdf')}")

    iterations = int(meta["kdf_iterations"])
    salt = b64d(meta["kdf_salt"])
    trigger_expected = bytes.fromhex(meta["trigger_hmac"])
    iv = b64d(meta["vault_iv"])
    ciphertext = b64d(meta["vault_ct"])
    ciphertext_hmac_expected = bytes.fromhex(meta["vault_hmac"])

    vault_key, vault_mac_key, trigger_mac_key = derive_keys(trigger_hex, salt, iterations)
    if not hmac.compare_digest(mac(trigger_mac_key, trigger_hex.encode("ascii")), trigger_expected):
        return None
    if not hmac.compare_digest(mac(vault_mac_key, ciphertext), ciphertext_hmac_expected):
        return None

    try:
        raw = aes_cbc_decrypt_raw(vault_key, iv, ciphertext)
    except Exception:
        return None
    if not raw.startswith(MAGIC):
        return None
    return raw[len(MAGIC):].decode("utf-8")


def encrypt_wasm(wasm_input: Path, secret: str, output: Path) -> None:
    if not wasm_input.exists():
        raise FileNotFoundError(wasm_input)
    key = hashlib.sha256(secret.encode("utf-8")).digest()
    iv, ciphertext = aes_cbc_encrypt_raw(key, wasm_input.read_bytes())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(iv + ciphertext)


def build(args: argparse.Namespace) -> None:
    trigger = require_trigger(args.trigger)
    secret = require_key_material(args.secret)

    model = create_tiny_bait_model()
    embed_vault(model, trigger, secret, args.iterations)

    model_output = Path(args.model_output)
    model_output.parent.mkdir(parents=True, exist_ok=True)
    onnx.save(model, str(model_output))
    digest = hashlib.sha256(model_output.read_bytes()).hexdigest()
    model_output.with_suffix(model_output.suffix + ".sha256").write_text(
        f"{digest}  {model_output.name}\n",
        encoding="utf-8",
    )

    print(f"[+] ONNX bait vault: {model_output} ({model_output.stat().st_size} bytes)")
    print(f"[+] SHA-256: {digest}")

    if args.wasm_input:
        wasm_input = Path(args.wasm_input)
        wasm_output = Path(args.wasm_output)
        encrypt_wasm(wasm_input, secret, wasm_output)
        print(f"[+] Encrypted WASM: {wasm_output} ({wasm_output.stat().st_size} bytes)")


def verify(args: argparse.Namespace) -> None:
    trigger = require_trigger(args.trigger)
    secret = unlock_secret(trigger, Path(args.model))
    if secret is None:
        print("[-] Wrong trigger or tampered vault")
        raise SystemExit(1)
    print(f"[+] UNLOCKED: {secret}")


def fingerprint(args: argparse.Namespace) -> None:
    combined, digest = compute_windows_fingerprint()
    if args.show_components:
        print(combined)
    print(digest)


def main() -> None:
    parser = argparse.ArgumentParser(prog="build.py")
    sub = parser.add_subparsers(dest="cmd", required=True)

    build_parser = sub.add_parser("build", help="generate ONNX vault and optionally encrypt WASM")
    build_parser.add_argument("--trigger", required=True, metavar="HEX64")
    build_parser.add_argument("--secret", required=True, help="32-character key material")
    build_parser.add_argument("--model-output", default="assets/model.onnx")
    build_parser.add_argument("--wasm-input", default="")
    build_parser.add_argument("--wasm-output", default="assets/license_module.wasm.aes")
    build_parser.add_argument("--iterations", type=int, default=DEFAULT_KDF_ITERATIONS)
    build_parser.set_defaults(func=build)

    verify_parser = sub.add_parser("verify", help="verify and unlock an ONNX vault")
    verify_parser.add_argument("--trigger", required=True, metavar="HEX64")
    verify_parser.add_argument("--model", default="assets/model.onnx")
    verify_parser.set_defaults(func=verify)

    fingerprint_parser = sub.add_parser(
        "fingerprint",
        help="print the Windows environment fingerprint hash used as --trigger",
    )
    fingerprint_parser.add_argument(
        "--show-components",
        action="store_true",
        help="also print the pre-hash MachineGuid/volume/SID string",
    )
    fingerprint_parser.set_defaults(func=fingerprint)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
