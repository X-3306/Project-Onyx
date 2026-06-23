from __future__ import annotations

import argparse
from pathlib import Path

import build


TRIGGER = "a" * 64
SECRET = "A" * 32
STEGO_KEY = "onxs1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"


def test_build_embeds_weight_vault_without_breaking_metadata_vault(tmp_path: Path) -> None:
    model_path = tmp_path / "model.onnx"

    build.build(
        argparse.Namespace(
            trigger=TRIGGER,
            secret=SECRET,
            model_output=str(model_path),
            wasm_input="",
            wasm_output=str(tmp_path / "license_module.wasm.aes"),
            iterations=1_000,
        )
    )

    assert build.unlock_secret(TRIGGER, model_path) == SECRET
    assert build.unlock_secret_from_weight_vault(TRIGGER, model_path) == SECRET


def test_weight_vault_generation_keeps_existing_metadata_unlock_behavior(tmp_path: Path) -> None:
    model_path = tmp_path / "model.onnx"

    build.build(
        argparse.Namespace(
            trigger=TRIGGER,
            secret=SECRET,
            model_output=str(model_path),
            wasm_input="",
            wasm_output=str(tmp_path / "license_module.wasm.aes"),
            iterations=1_000,
        )
    )

    assert build.unlock_secret(TRIGGER, model_path) == SECRET
    assert build.unlock_secret_from_weight_vault(TRIGGER, model_path) == SECRET
