"""Internal multimodal severity service. Only the dashboard can reach it."""
from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile

from ..ml.image import open_image
from ..ml.infer import SeverityModel

app = FastAPI(title="Disaster Sentinel classifier", docs_url=None, redoc_url=None, openapi_url=None)
MAX_IMAGE = 8 * 1024 * 1024
_model: SeverityModel | None = None


def model() -> SeverityModel:
    global _model
    if _model is None:
        _model = SeverityModel(Path(os.environ.get("MODEL_DIR", "models")))
    return _model


def require_token(x_internal_token: Annotated[str | None, Header()] = None) -> None:
    expected = os.environ.get("CLASSIFIER_TOKEN", "")
    if not expected or not hmac.compare_digest(x_internal_token or "", expected):
        raise HTTPException(401, "Invalid internal token")


@app.get("/healthz")
def healthz() -> dict:
    try:
        m = model()
    except FileNotFoundError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "version": m.version, "trained_on": m.trained_on, "test_macro_f1": m.test_macro_f1}


@app.post("/predict")
def predict(
    x_internal_token: Annotated[str | None, Header()] = None,
    text: Annotated[str | None, Form(max_length=5000)] = None,
    image: Annotated[UploadFile | None, File()] = None,
) -> dict:
    require_token(x_internal_token)
    picture = None
    if image is not None:
        data = image.file.read(MAX_IMAGE + 1)
        if len(data) > MAX_IMAGE:
            raise HTTPException(413, "Image larger than 8 MB")
        if data:
            try:
                picture = open_image(data)
            except Exception as exc:
                raise HTTPException(422, "This file could not be read as an image") from exc
    try:
        return model().predict(text, picture)
    except FileNotFoundError as exc:
        raise HTTPException(503, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
