from __future__ import annotations

import argparse
from pathlib import Path

import pytest

import build


TRIGGER = "b" * 64
SECRET = "B" * 32


def _build_reference(path: Path) -> None:
    build.build(
        argparse.Namespace(
            trigger=TRIGGER,
            secret=SECRET,
            model_output=str(path),
            wasm_input="",
            wasm_output=str(path.with_suffix(".wasm.aes")),
            iterations=1_000,
        )
    )


def test_downlink_update_round_trips_set_status_directive(tmp_path: Path) -> None:
    reference = tmp_path / "reference.onnx"
    update = tmp_path / "update.onnx"
    _build_reference(reference)

    build.build_downlink_update(
        argparse.Namespace(
            trigger=TRIGGER,
            reference_model=str(reference),
            cover_model="",
            output=str(update),
            command="set_status",
            status="lab_downlink_ack",
            nonce="nonce-001",
            expires_unix=4_102_444_800,
            iterations=1_000,
            natural_min_abs_delta=1e-5,
        )
    )

    directive = build.extract_downlink_directive(
        TRIGGER,
        reference,
        update,
        natural_min_abs_delta=1e-5,
        now_unix=1_800_000_000,
    )

    assert directive == {
        "type": "set_status",
        "status": "lab_downlink_ack",
        "nonce": "nonce-001",
        "expires_unix": 4_102_444_800,
    }


def test_downlink_update_round_trips_heartbeat_ack(tmp_path: Path) -> None:
    reference = tmp_path / "reference.onnx"
    update = tmp_path / "update.onnx"
    _build_reference(reference)

    build.build_downlink_update(
        argparse.Namespace(
            trigger=TRIGGER,
            reference_model=str(reference),
            cover_model="",
            output=str(update),
            command="heartbeat_ack",
            status="",
            nonce="nonce-002",
            expires_unix=4_102_444_800,
            iterations=1_000,
            natural_min_abs_delta=1e-5,
        )
    )

    directive = build.extract_downlink_directive(
        TRIGGER,
        reference,
        update,
        natural_min_abs_delta=1e-5,
        now_unix=1_800_000_000,
    )

    assert directive["type"] == "heartbeat_ack"
    assert directive["nonce"] == "nonce-002"


def test_downlink_rejects_non_whitelisted_directive(tmp_path: Path) -> None:
    reference = tmp_path / "reference.onnx"
    update = tmp_path / "update.onnx"
    _build_reference(reference)

    with pytest.raises(ValueError, match="not allowed"):
        build.build_downlink_update(
            argparse.Namespace(
                trigger=TRIGGER,
                reference_model=str(reference),
                cover_model="",
                output=str(update),
                command="run_shell",
                status="calc.exe",
                nonce="nonce-003",
                expires_unix=4_102_444_800,
                iterations=1_000,
                natural_min_abs_delta=1e-5,
            )
        )


def test_plain_model_update_without_downlink_is_ignored(tmp_path: Path) -> None:
    reference = tmp_path / "reference.onnx"
    update = tmp_path / "plain_update.onnx"
    _build_reference(reference)
    model = build.load_model_as_cover_update(reference, natural_min_abs_delta=1e-5)
    build.onnx.save(model, str(update))

    assert (
        build.extract_downlink_directive(
            TRIGGER,
            reference,
            update,
            natural_min_abs_delta=1e-5,
            now_unix=1_800_000_000,
        )
        is None
    )
