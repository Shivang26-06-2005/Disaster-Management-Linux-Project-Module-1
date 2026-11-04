"""Train and evaluate the multimodal severity model (slide 9 steps 3-5, slide 16 order).

    python -m sentinel.ml.train --data data/crisismmd --out models

Runs on a laptop CPU. Image features are cached after the first run. Everything is
tuned on the dev split, and the test split is scored once at the end. All numbers
are written to reports/, so report them from there and not from memory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score
from sklearn.model_selection import GroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .data import LABELS, Example, clean_text, load_dataset
from .image import ImageEncoder, open_image, preprocess

SEED = 42
FUSION_MODEL_VERSION = "tfidf-mobilenetv2-late-fusion-1"


def image_features(encoder: ImageEncoder, examples: list[Example], cache: Path, flip: bool) -> np.ndarray:
    key = hashlib.sha256("|".join(str(e.image) for e in examples).encode()).hexdigest()[:16]
    path = cache / f"img_{key}_{'flip' if flip else 'plain'}.npy"
    if path.exists():
        return np.load(path)
    out = np.zeros((len(examples), 1280), dtype=np.float32)
    batch, slots = [], []
    for i, ex in enumerate(examples):
        try:
            batch.append(preprocess(open_image(ex.image), flip=flip))
            slots.append(i)
        except Exception as exc:  # A corrupt image should not stop a long run.
            print(f"  skipped unreadable image {ex.image}: {exc}")
        if len(batch) == 16 or (i == len(examples) - 1 and batch):
            out[slots] = ImageEncoder.encode_arrays(encoder, np.stack(batch))
            batch, slots = [], []
        if (i + 1) % 500 == 0:
            print(f"  encoded {i + 1}/{len(examples)} images", flush=True)
    cache.mkdir(parents=True, exist_ok=True)
    np.save(path, out)
    return out


def fit_text(texts: list[str], y: np.ndarray, C: float) -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_df=0.9, sublinear_tf=True,
                                  max_features=40000)),
        ("clf", LogisticRegression(C=C, class_weight="balanced", max_iter=2000, random_state=SEED)),
    ]).fit(texts, y)


def fit_image(x: np.ndarray, y: np.ndarray, C: float) -> Pipeline:
    return Pipeline([
        ("scale", StandardScaler()),
        ("clf", LogisticRegression(C=C, class_weight="balanced", max_iter=2000, random_state=SEED)),
    ]).fit(x, y)


def macro_f1(y: np.ndarray, p: np.ndarray) -> float:
    return f1_score(y, p.argmax(1), average="macro")


def scale_temperature(p: np.ndarray, t: float) -> np.ndarray:
    logits = np.log(np.clip(p, 1e-9, 1.0)) / t
    logits -= logits.max(axis=1, keepdims=True)
    q = np.exp(logits)
    return q / q.sum(axis=1, keepdims=True)


def expected_calibration_error(y: np.ndarray, p: np.ndarray, bins: int = 10) -> float:
    conf, correct = p.max(1), p.argmax(1) == y
    ece = 0.0
    for lo in np.linspace(0, 1, bins, endpoint=False):
        mask = (conf > lo) & (conf <= lo + 1 / bins)
        if mask.any():
            ece += mask.mean() * abs(correct[mask].mean() - conf[mask].mean())
    return float(ece)


def fit_temperature(y: np.ndarray, p: np.ndarray) -> float:
    grid = np.arange(0.1, 3.01, 0.05)
    nll = [-np.log(np.clip(scale_temperature(p, t)[np.arange(len(y)), y], 1e-9, 1)).mean() for t in grid]
    return float(grid[int(np.argmin(nll))])


def score(y: np.ndarray, p: np.ndarray) -> dict:
    pred = p.argmax(1)
    return {
        "macro_f1": round(float(f1_score(y, pred, average="macro")), 4),
        "weighted_f1": round(float(f1_score(y, pred, average="weighted")), 4),
        "accuracy": round(float(accuracy_score(y, pred)), 4),
        "per_class_f1": {
            LABELS[i]: round(float(v), 4)
            for i, v in enumerate(f1_score(y, pred, average=None, labels=range(len(LABELS))))
        },
        "ece": round(expected_calibration_error(y, p), 4),
        "confusion_matrix": confusion_matrix(y, pred, labels=range(len(LABELS))).tolist(),
    }


def paired_bootstrap(y: np.ndarray, a: np.ndarray, b: np.ndarray, n: int = 2000) -> dict:
    """95% interval on macro-F1(a) minus macro-F1(b), resampling the same test items."""
    rng = np.random.default_rng(SEED)
    pa, pb = a.argmax(1), b.argmax(1)
    diffs, values = [], []
    for _ in range(n):
        idx = rng.integers(0, len(y), len(y))
        fa = f1_score(y[idx], pa[idx], average="macro", zero_division=0)
        diffs.append(fa - f1_score(y[idx], pb[idx], average="macro", zero_division=0))
        values.append(fa)
    return {
        "difference": round(float(macro_f1(y, a) - macro_f1(y, b)), 4),
        "ci95": [round(float(np.percentile(diffs, 2.5)), 4), round(float(np.percentile(diffs, 97.5)), 4)],
        "a_ci95": [round(float(np.percentile(values, 2.5)), 4), round(float(np.percentile(values, 97.5)), 4)],
    }


def best_fusion_weight(y: np.ndarray, pt: np.ndarray, pi: np.ndarray) -> tuple[float, float]:
    best = (0.5, -1.0)
    for w in np.arange(0.0, 1.0001, 0.05):
        s = macro_f1(y, w * pi + (1 - w) * pt)
        if s > best[1] + 1e-9:
            best = (float(round(w, 2)), float(s))
    return best


def run(data: Path, out: Path, reports: Path, extractor: Path) -> dict:
    started = time.time()
    splits = load_dataset(data)
    train, dev, test = splits["train"], splits["dev"], splits["test"]
    print("loaded", {k: len(v) for k, v in splits.items()})
    y_train = np.array([e.label for e in train])
    y_dev = np.array([e.label for e in dev])
    y_test = np.array([e.label for e in test])

    train_tweets = {e.tweet_id for e in train + dev}
    test_tweets = {e.tweet_id for e in test}
    train_img, test_img = {e.image_id for e in train + dev}, {e.image_id for e in test}
    leakage = {
        "tweets_in_train_and_test": len(train_tweets & test_tweets),
        "images_in_train_and_test": len(train_img & test_img),
    }

    t_train = [clean_text(e.text) for e in train]
    t_dev = [clean_text(e.text) for e in dev]
    t_test = [clean_text(e.text) for e in test]

    encoder = ImageEncoder(extractor)
    cache = out / "cache"
    x_train = image_features(encoder, train, cache, flip=False)
    x_flip = image_features(encoder, train, cache, flip=True)   # slide 9: augmentation
    x_dev = image_features(encoder, dev, cache, flip=False)
    x_dev_flip = image_features(encoder, dev, cache, flip=True)
    x_test = image_features(encoder, test, cache, flip=False)

    # Tune on 5-fold cross-validation over train + dev, grouped by tweet so one tweet
    # never sits on both sides. One 529-item dev split proved too noisy to choose a
    # fusion weight: small changes moved the weight from 0.25 to 0.95.
    tv = train + dev
    y_tv = np.concatenate([y_train, y_dev])
    t_tv = t_train + t_dev
    x_tv = np.vstack([x_train, x_dev])
    x_tv_flip = np.vstack([x_flip, x_dev_flip])
    groups = np.array([e.tweet_id for e in tv])
    folds = list(GroupKFold(n_splits=5).split(x_tv, y_tv, groups))

    text_grid = [0.01, 0.03, 0.1, 0.3, 1.0, 3.0, 10.0]
    image_grid = [0.00003, 0.0001, 0.0003, 0.001, 0.003, 0.01, 0.03, 0.1]
    oof_text, oof_image = {}, {}
    for c in text_grid:
        oof = np.zeros((len(tv), len(LABELS)))
        for fit_idx, held in folds:
            model = fit_text([t_tv[i] for i in fit_idx], y_tv[fit_idx], c)
            oof[held] = model.predict_proba([t_tv[i] for i in held])
        oof_text[c] = oof
    for c in image_grid:
        oof = np.zeros((len(tv), len(LABELS)))
        for fit_idx, held in folds:
            x_fit = np.vstack([x_tv[fit_idx], x_tv_flip[fit_idx]])
            model = fit_image(x_fit, np.concatenate([y_tv[fit_idx], y_tv[fit_idx]]), c)
            oof[held] = model.predict_proba(x_tv[held])
        oof_image[c] = oof

    best = (-1.0, text_grid[0], image_grid[0], 0.5)
    for tc in text_grid:
        for ic in image_grid:
            w, f1 = best_fusion_weight(y_tv, oof_text[tc], oof_image[ic])
            if f1 > best[0]:
                best = (f1, tc, ic, w)
    cv_f1, text_c, img_c, weight = best
    text_only_c = max(text_grid, key=lambda c: macro_f1(y_tv, oof_text[c]))
    image_only_c = max(image_grid, key=lambda c: macro_f1(y_tv, oof_image[c]))
    print("chosen", {"text_C": text_c, "image_C": img_c, "image_weight": weight, "cv_macro_f1": round(cv_f1, 4)}, flush=True)

    p_oof_f = weight * oof_image[img_c] + (1 - weight) * oof_text[text_c]
    temps = {
        "text": fit_temperature(y_tv, oof_text[text_c]),
        "image": fit_temperature(y_tv, oof_image[img_c]),
        "fused": fit_temperature(y_tv, p_oof_f),
    }
    cv_scores = {
        "text_only_best": round(macro_f1(y_tv, oof_text[text_only_c]), 4),
        "image_only_best": round(macro_f1(y_tv, oof_image[image_only_c]), 4),
        "fused": round(cv_f1, 4),
    }

    # Final fit on all of train + dev with the settings chosen above.
    x_aug = np.vstack([x_tv, x_tv_flip])
    y_aug = np.concatenate([y_tv, y_tv])
    text_model = fit_text(t_tv, y_tv, text_c)
    image_model = fit_image(x_aug, y_aug, img_c)

    # Test split: scored exactly once, after every choice above is fixed.
    p_t = scale_temperature(text_model.predict_proba(t_test), temps["text"])
    p_i = scale_temperature(image_model.predict_proba(x_test), temps["image"])
    p_f = scale_temperature(
        weight * image_model.predict_proba(x_test) + (1 - weight) * text_model.predict_proba(t_test),
        temps["fused"],
    )
    majority = np.zeros_like(p_f)
    majority[:, Counter(y_tv.tolist()).most_common(1)[0][0]] = 1.0

    # The official split keeps images apart but some tweets appear on both sides,
    # with different images. Score again without them to show their effect.
    unseen = np.array([e.tweet_id not in train_tweets for e in test])
    unseen_tweets = {
        "n": int(unseen.sum()),
        "text_macro_f1": round(macro_f1(y_test[unseen], p_t[unseen]), 4),
        "image_macro_f1": round(macro_f1(y_test[unseen], p_i[unseen]), 4),
        "fused_macro_f1": round(macro_f1(y_test[unseen], p_f[unseen]), 4),
    }

    # Generalisation to an unseen disaster: hold out each event in turn.
    all_ex = train + dev + test
    all_x = np.vstack([x_train, x_dev, x_test])
    all_t = t_train + t_dev + t_test
    all_y = np.array([e.label for e in all_ex])
    events = np.array([e.event for e in all_ex])
    loeo = {}
    for event in sorted(set(events.tolist())):
        mask = events == event
        tr_idx, te_idx = np.where(~mask)[0], np.where(mask)[0]
        lt = fit_text([all_t[i] for i in tr_idx], all_y[tr_idx], text_c)
        li = fit_image(all_x[tr_idx], all_y[tr_idx], img_c)
        pt = lt.predict_proba([all_t[i] for i in te_idx])
        pi = li.predict_proba(all_x[te_idx])
        pf = weight * pi + (1 - weight) * pt
        loeo[event] = {
            "n": int(mask.sum()),
            "text_macro_f1": round(macro_f1(all_y[te_idx], pt), 4),
            "image_macro_f1": round(macro_f1(all_y[te_idx], pi), 4),
            "fused_macro_f1": round(macro_f1(all_y[te_idx], pf), 4),
        }

    report = {
        "dataset": "CrisisMMD v2.0 damage task, agreed-label split",
        "sizes": {k: len(v) for k, v in splits.items()},
        "class_counts_train": {LABELS[k]: v for k, v in sorted(Counter(y_train.tolist()).items())},
        "leakage_check": leakage,
        "chosen": {"text_C": text_c, "image_C": img_c, "image_weight": weight, "temperature": temps},
        "cross_validation_macro_f1": cv_scores,
        "test": {
            "majority_baseline": score(y_test, majority),
            "text_only": score(y_test, p_t),
            "image_only": score(y_test, p_i),
            "fused": score(y_test, p_f),
        },
        "test_excluding_tweets_seen_in_train": unseen_tweets,
        "fused_minus_image": paired_bootstrap(y_test, p_f, p_i),
        "fused_minus_text": paired_bootstrap(y_test, p_f, p_t),
        "leave_one_event_out": loeo,
        "train_seconds": round(time.time() - started, 1),
    }

    out.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "version": FUSION_MODEL_VERSION,
        "labels": LABELS,
        "text": text_model,
        "image": image_model,
        "image_weight": weight,
        "temperature": temps,
        "trained_on": report["dataset"],
        "test_macro_f1": report["test"]["fused"]["macro_f1"],
    }, out / "severity_model.joblib")
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "classifier_eval.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=Path("models"))
    ap.add_argument("--reports", type=Path, default=Path("reports"))
    ap.add_argument("--extractor", type=Path, default=Path("models/mobilenetv2_features.onnx"))
    args = ap.parse_args()
    report = run(args.data, args.out, args.reports, args.extractor)
    print(json.dumps(report["test"], indent=2))
    print(json.dumps({k: report[k] for k in ("fused_minus_image", "fused_minus_text", "leakage_check")}, indent=2))


if __name__ == "__main__":
    main()
