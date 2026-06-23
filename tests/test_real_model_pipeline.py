from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

import onnx
from onnx import TensorProto

import build


TRIGGER = "c" * 64
SECRET = "C" * 32


def _build_args(tmp_path: Path, model_path: Path) -> argparse.Namespace:
    return argparse.Namespace(
        trigger=TRIGGER,
        secret=SECRET,
        model_output=str(model_path),
        wasm_input="",
        wasm_output=str(tmp_path / "license_module.wasm.aes"),
        iterations=1_000,
        base_model="",
    )


def test_default_build_uses_real_squeezenet_reference_model(tmp_path: Path) -> None:
    model_path = tmp_path / "model.onnx"

    build.build(_build_args(tmp_path, model_path))

    model = onnx.load(str(model_path))
    onnx.checker.check_model(model)

    assert model.graph.input[0].name == "data_0"
    input_type = model.graph.input[0].type.tensor_type
    assert input_type.elem_type == TensorProto.FLOAT
    assert [dim.dim_value for dim in input_type.shape.dim] == [1, 3, 224, 224]
    assert build.unlock_secret(TRIGGER, model_path) == SECRET
    assert build.unlock_secret_from_weight_vault(TRIGGER, model_path) == SECRET


def test_lab_finetune_update_is_seeded_and_produces_natural_candidates(tmp_path: Path) -> None:
    reference_path = tmp_path / "reference.onnx"
    update_a_path = tmp_path / "update-a.onnx"
    update_b_path = tmp_path / "update-b.onnx"
    build.build(_build_args(tmp_path, reference_path))

    update_a = build.create_lab_finetune_update(
        reference_path,
        natural_min_abs_delta=1e-5,
        seed=1337,
        modify_fraction=0.08,
        noise_scale=4e-5,
    )
    update_b = build.create_lab_finetune_update(
        reference_path,
        natural_min_abs_delta=1e-5,
        seed=1337,
        modify_fraction=0.08,
        noise_scale=4e-5,
    )
    onnx.save(update_a, str(update_a_path))
    onnx.save(update_b, str(update_b_path))

    assert hashlib.sha256(update_a_path.read_bytes()).hexdigest() == hashlib.sha256(
        update_b_path.read_bytes()
    ).hexdigest()

    candidates = build.natural_candidate_positions(
        onnx.load(str(reference_path)),
        update_a,
        natural_min_abs_delta=1e-5,
    )
    assert len(candidates) > 50_000
    assert len(candidates) < len(build.float32_weight_lsb_bits(update_a))


def test_downlink_build_can_use_lab_finetune_cover_with_real_model(tmp_path: Path) -> None:
    reference_path = tmp_path / "reference.onnx"
    update_path = tmp_path / "downlink_update.onnx"
    build.build(_build_args(tmp_path, reference_path))

    build.build_downlink_update(
        argparse.Namespace(
            trigger=TRIGGER,
            reference_model=str(reference_path),
            cover_model="",
            output=str(update_path),
            command="set_status",
            status="real_model_downlink_ack",
            nonce="real-model-001",
            expires_unix=4_102_444_800,
            iterations=1_000,
            natural_min_abs_delta=1e-5,
            cover_seed=2026,
            cover_fraction=0.08,
            cover_noise_scale=4e-5,
        )
    )

    directive = build.extract_downlink_directive(
        TRIGGER,
        reference_path,
        update_path,
        natural_min_abs_delta=1e-5,
        now_unix=1_800_000_000,
    )

    assert directive == {
        "type": "set_status",
        "status": "real_model_downlink_ack",
        "nonce": "real-model-001",
        "expires_unix": 4_102_444_800,
    }
