from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from sentinel.ml.data import clean_text, normalise_label
from sentinel.ml.guidance import recommend
from sentinel.ml.train import best_fusion_weight, expected_calibration_error, scale_temperature

MODELS = Path(__file__).resolve().parents[1] / "models"


def test_clean_text_removes_noise_and_keeps_hashtag_words():
    raw = "RT @user: Floods!! hit #Chennai https://t.co/abc &amp; many houses are submerged"
    assert clean_text(raw) == "floods hit chennai many houses are submerged"
    assert clean_text(None) == ""


@pytest.mark.parametrize("raw,want", [
    ("severe_damage", "severe_damage"), ("Severe damage", "severe_damage"),
    ("Little or no damage", "little_or_no_damage"), ("dont_know_or_cant_judge", None),
])
def test_labels_normalise(raw, want):
    assert normalise_label(raw) == want


def test_temperature_keeps_ranking_and_sums_to_one():
    p = np.array([[0.6, 0.3, 0.1]])
    for t in (0.5, 1.0, 2.0):
        q = scale_temperature(p, t)
        assert q.argmax() == 0 and abs(q.sum() - 1) < 1e-9
    assert scale_temperature(p, 0.5).max() > 0.6 > scale_temperature(p, 2.0).max()


def test_ece_is_zero_when_confidence_matches_accuracy():
    y = np.array([0, 0, 0, 1])
    p = np.tile([0.75, 0.25, 0.0], (4, 1))
    assert expected_calibration_error(y, p) < 1e-9


def test_fusion_weight_prefers_the_better_modality():
    y = np.array([0, 1, 2, 0, 1, 2])
    good = np.eye(3)[y]
    bad = np.eye(3)[(y + 1) % 3]
    assert best_fusion_weight(y, bad, good)[0] > 0.5
    assert best_fusion_weight(y, good, bad)[0] < 0.5


def test_severe_advice_is_specific_and_caution_appears_when_unverified():
    advice = recommend("severe_damage", "flood", 0.8, "unverified")
    assert any("higher ground" in a for a in advice["actions"])
    assert "Verify" in advice["caution"]
    assert recommend("severe_damage", "flood", 0.8, "corroborated")["caution"] is None
    assert "low reliability" in recommend("mild_damage", None, 0.3, "corroborated")["caution"]


def test_little_damage_does_not_send_rescue():
    advice = recommend("little_or_no_damage", "flood", 0.9, "corroborated")
    assert not any("rescue" in a.lower() and "No immediate" not in a for a in advice["actions"])


@pytest.fixture(scope="module")
def model():
    if not (MODELS / "severity_model.joblib").exists():
        pytest.skip("Model not trained")
    from sentinel.ml.infer import SeverityModel

    return SeverityModel(MODELS)


def test_prediction_modes_and_probabilities(model):
    image = Image.effect_noise((300, 200), 60).convert("RGB")
    text = "many houses destroyed and people trapped after the flood"
    both = model.predict(text, image)
    assert both["mode"] == "text_and_image"
    assert abs(sum(both["probabilities"].values()) - 1) < 1e-3
    assert model.predict(text)["mode"] == "text_only"
    assert model.predict(None, image)["mode"] == "image_only"
    assert model.predict(text)["reliability"] < 1.0
    with pytest.raises(ValueError):
        model.predict("   ", None)


def test_explanations_come_from_the_model(model):
    image = Image.effect_noise((300, 200), 60).convert("RGB")
    result = model.predict("houses destroyed by the flood", image)
    assert all(t["term"] for t in result["explanation"]["text_terms"])
    grid = np.array(result["explanation"]["image_occlusion_grid"])
    assert grid.shape == (7, 7)
    assert result["explanation"]["image_heatmap_jpeg"].startswith("/9j/")


def test_text_explanation_terms_add_up_to_the_linear_score(model):
    cleaned = clean_text("houses destroyed flood")
    tfidf = model.text_model.named_steps["tfidf"]
    clf = model.text_model.named_steps["clf"]
    vector = tfidf.transform([cleaned])
    index = int(np.argmax(model.text_model.predict_proba([cleaned])[0]))
    linear = float(vector.dot(clf.coef_[index])[0])
    terms = model._text_terms(cleaned, index, top=100)
    assert abs(sum(t["weight"] for t in terms) - linear) < 0.01


def test_unreadable_upload_is_handled():
    from sentinel.ml.image import open_image

    with pytest.raises(Exception):
        open_image(b"this is not an image")
