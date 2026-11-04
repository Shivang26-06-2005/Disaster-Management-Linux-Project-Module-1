"""Severity prediction with explanations (slide 9 step 5, slide 11).

Explanations come from the model's own arithmetic instead of a separate approximation:
* Text: logistic regression is linear, so each word's weight times its TF-IDF value
  is exactly what it added to the score.
* Image: occlusion. Grey out one region at a time and measure how far the severity
  probability falls. No gradients are needed, so this runs on ONNX on a CPU. It plays
  the role the deck gives Grad-CAM.
* Fusion: the reply shows each modality's vote, and disagreement lowers reliability.
"""
from __future__ import annotations

import base64
import io
from pathlib import Path

import joblib
import numpy as np
from PIL import Image

from .data import LABEL_DISPLAY, LABELS, clean_text
from .image import SIZE, ImageEncoder, preprocess
from .train import scale_temperature


def _probs(values: np.ndarray) -> dict[str, float]:
    return {LABELS[i]: round(float(v), 4) for i, v in enumerate(values)}


class SeverityModel:
    def __init__(self, model_dir: Path):
        path = Path(model_dir) / "severity_model.joblib"
        if not path.exists():
            raise FileNotFoundError(f"{path} not found. Train the model first, see the README.")
        # joblib runs code when loading, so only load a file you trained or generated yourself.
        bundle = joblib.load(path)
        self.version = bundle["version"]
        self.text_model = bundle["text"]
        self.image_model = bundle["image"]
        self.weight = bundle["image_weight"]
        self.temperature = bundle["temperature"]
        self.trained_on = bundle["trained_on"]
        self.test_macro_f1 = bundle.get("test_macro_f1")
        self.encoder = ImageEncoder(Path(model_dir) / "mobilenetv2_features.onnx")

    def _text_terms(self, cleaned: str, class_index: int, top: int = 6) -> list[dict]:
        tfidf = self.text_model.named_steps["tfidf"]
        clf = self.text_model.named_steps["clf"]
        vector = tfidf.transform([cleaned]).tocoo()
        names = tfidf.get_feature_names_out()
        terms = [
            {"term": names[j], "weight": round(float(v * clf.coef_[class_index, j]), 4)}
            for j, v in zip(vector.col, vector.data)
        ]
        terms.sort(key=lambda t: abs(t["weight"]), reverse=True)
        return terms[:top]

    def _occlusion(self, img: Image.Image, class_index: int, grid: int = 7) -> tuple[str, list[list[float]]]:
        base = preprocess(img)
        cell = SIZE // grid
        batch = [base]
        for row in range(grid):
            for col in range(grid):
                masked = base.copy()
                masked[:, row * cell:(row + 1) * cell, col * cell:(col + 1) * cell] = 0.0
                batch.append(masked)
        probs = self.image_model.predict_proba(self.encoder.encode_arrays(np.stack(batch), batch=16))
        drops = (probs[0, class_index] - probs[1:, class_index]).reshape(grid, grid)
        heat = np.clip(drops, 0, None)
        if heat.max() > 0:
            heat = heat / heat.max()
        overlay = img.convert("RGB").resize((SIZE, SIZE))
        arr = np.asarray(overlay, dtype=np.float32)
        mask = np.asarray(Image.fromarray((heat * 255).astype(np.uint8)).resize((SIZE, SIZE), Image.BILINEAR),
                          dtype=np.float32) / 255.0
        tint = np.stack([mask * 255, mask * 90, np.zeros_like(mask)], axis=-1)
        blended = arr * (1 - 0.55 * mask[..., None]) + tint * 0.55
        buffer = io.BytesIO()
        Image.fromarray(blended.clip(0, 255).astype(np.uint8)).save(buffer, "JPEG", quality=80)
        return base64.b64encode(buffer.getvalue()).decode(), np.round(drops, 3).tolist()

    def predict(self, text: str | None = None, image: Image.Image | None = None, explain: bool = True) -> dict:
        cleaned = clean_text(text)
        has_text = bool(cleaned)
        has_image = image is not None
        if not has_text and not has_image:
            raise ValueError("Provide text, an image, or both")

        raw_t = self.text_model.predict_proba([cleaned])[0] if has_text else None
        raw_i = self.image_model.predict_proba(self.encoder.encode(image)[None])[0] if has_image else None

        if has_text and has_image:
            fused = scale_temperature(
                (self.weight * raw_i + (1 - self.weight) * raw_t)[None], self.temperature["fused"]
            )[0]
            mode = "text_and_image"
        elif has_text:
            fused = scale_temperature(raw_t[None], self.temperature["text"])[0]
            mode = "text_only"
        else:
            fused = scale_temperature(raw_i[None], self.temperature["image"])[0]
            mode = "image_only"

        index = int(np.argmax(fused))
        reliability = float(fused[index])
        disagreement = False
        result: dict = {
            "severity": LABELS[index],
            "severity_label": LABEL_DISPLAY[LABELS[index]],
            "probabilities": _probs(fused),
            "mode": mode,
            "model_version": self.version,
            "image_weight": self.weight if mode == "text_and_image" else None,
        }
        if has_text:
            p = scale_temperature(raw_t[None], self.temperature["text"])[0]
            result["text_probabilities"] = _probs(p)
        if has_image:
            p = scale_temperature(raw_i[None], self.temperature["image"])[0]
            result["image_probabilities"] = _probs(p)
        if has_text and has_image:
            disagreement = int(np.argmax(raw_t)) != int(np.argmax(raw_i))
            if disagreement:
                reliability *= 0.8  # Conflicting evidence is less trustworthy than the score alone.
        if not (has_text and has_image):
            reliability *= 0.9      # A single source is weaker evidence than two.
        result["reliability"] = round(reliability, 4)
        result["modalities_disagree"] = disagreement
        if explain:
            result["explanation"] = {}
            if has_text:
                result["explanation"]["text_terms"] = self._text_terms(cleaned, index)
            if has_image:
                heatmap, grid = self._occlusion(image, index)
                result["explanation"]["image_heatmap_jpeg"] = heatmap
                result["explanation"]["image_occlusion_grid"] = grid
        return result
