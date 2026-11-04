"""CNN visual features on CPU: MobileNetV2 through ONNX Runtime, no PyTorch needed.

The ONNX model zoo file outputs 1000 ImageNet scores. ``prepare_extractor`` cuts it
at the layer before the classifier, which gives a 1280-value visual description.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path

import numpy as np
from PIL import Image, ImageFile

ImageFile.LOAD_TRUNCATED_IMAGES = True
Image.MAX_IMAGE_PIXELS = 40_000_000

SOURCE_URL = (
    "https://media.githubusercontent.com/media/onnx/models/main/validated/vision/"
    "classification/mobilenet/model/mobilenetv2-12.onnx"
)
SOURCE_SHA256 = "c0c3f76d93fa3fd6580652a45618618a220fced18babf65774ed169de0432ad5"
_MEAN = np.array([0.485, 0.456, 0.406], dtype=np.float32).reshape(3, 1, 1)
_STD = np.array([0.229, 0.224, 0.225], dtype=np.float32).reshape(3, 1, 1)
SIZE = 224


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare_extractor(source: Path, target: Path) -> Path:
    """Truncate the pretrained model at its 1280-value pooled output."""
    import onnx

    model = onnx.load(str(source))
    graph = model.graph
    gemm = next(n for n in reversed(graph.node) if n.op_type == "Gemm")
    feature_name = gemm.input[0]
    keep = list(graph.node)[: list(graph.node).index(gemm)]
    del graph.node[:]
    graph.node.extend(keep)
    del graph.output[:]
    graph.output.extend([onnx.helper.make_tensor_value_info(feature_name, onnx.TensorProto.FLOAT, None)])
    used = {i for n in graph.node for i in n.input}
    kept_init = [i for i in graph.initializer if i.name in used]
    del graph.initializer[:]
    graph.initializer.extend(kept_init)
    onnx.save(model, str(target))
    return target


def preprocess(img: Image.Image, flip: bool = False) -> np.ndarray:
    img = img.convert("RGB")
    w, h = img.size
    scale = 256 / min(w, h)
    img = img.resize((max(SIZE, round(w * scale)), max(SIZE, round(h * scale))), Image.BILINEAR)
    w, h = img.size
    left, top = (w - SIZE) // 2, (h - SIZE) // 2
    img = img.crop((left, top, left + SIZE, top + SIZE))
    if flip:
        img = img.transpose(Image.FLIP_LEFT_RIGHT)
    arr = np.asarray(img, dtype=np.float32).transpose(2, 0, 1) / 255.0
    return (arr - _MEAN) / _STD


class ImageEncoder:
    def __init__(self, model_path: Path):
        import onnxruntime as ort

        options = ort.SessionOptions()
        options.log_severity_level = 3
        self.session = ort.InferenceSession(
            str(model_path), options, providers=["CPUExecutionProvider"]
        )
        self.input = self.session.get_inputs()[0].name
        self.output = self.session.get_outputs()[0].name

    def encode_arrays(self, arrays: np.ndarray, batch: int = 8) -> np.ndarray:
        out = []
        for i in range(0, len(arrays), batch):
            result = self.session.run([self.output], {self.input: arrays[i:i + batch]})[0]
            out.append(result.reshape(result.shape[0], -1))
        return np.concatenate(out, axis=0)

    def encode(self, img: Image.Image) -> np.ndarray:
        return self.encode_arrays(preprocess(img)[None])[0]


def open_image(data: bytes | Path) -> Image.Image:
    source = io.BytesIO(data) if isinstance(data, (bytes, bytearray)) else data
    img = Image.open(source)
    img.load()
    return img.convert("RGB")
