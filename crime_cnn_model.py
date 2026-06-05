# =============================================================================
#  crime_cnn_model.py
#  TensorFlow/Keras CNN Architecture for Forensic Crime Classification
#
#  Architecture:
#    EfficientNetV2-S backbone (pretrained ImageNet) + custom head
#    Fine-tuned for 16 forensic crime categories
#
#  Install:
#    pip install tensorflow ultralytics opencv-python numpy pillow
# =============================================================================

import os
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, regularizers
from tensorflow.keras.applications import EfficientNetV2S
from tensorflow.keras.applications.efficientnet_v2 import preprocess_input

# ---------------------------------------------------------------------------
# Crime classes — 16 forensic categories
# ---------------------------------------------------------------------------
CRIME_CLASSES = [
    "Homicide",
    "Armed Robbery",
    "Violent Assault",
    "Kidnapping",
    "Drug Trafficking",
    "Drug Possession",
    "Weapons Crime",
    "Road Accident",
    "Hit and Run",
    "Arson",
    "Explosion Incident",
    "Terrorism",
    "Cybercrime",
    "Financial Fraud",
    "Suspicious Activity",
    "No Crime",
]

NUM_CLASSES  = len(CRIME_CLASSES)
IMAGE_SIZE   = (224, 224)   # EfficientNetV2-S input
IMAGE_SHAPE  = (224, 224, 3)

# Confidence threshold — below this, fallback rules are consulted
CNN_CONFIDENCE_THRESHOLD = 0.50


# =============================================================================
#  Model builder
# =============================================================================

def build_model(
    num_classes: int = NUM_CLASSES,
    image_shape: tuple = IMAGE_SHAPE,
    dropout_rate: float = 0.40,
    l2_reg: float = 1e-4,
    freeze_backbone: bool = True,
) -> keras.Model:
    """
    Build EfficientNetV2-S transfer learning model for crime classification.

    Args:
        num_classes    : number of output crime categories
        image_shape    : input shape (H, W, C)
        dropout_rate   : dropout before final dense
        l2_reg         : L2 regularisation on dense layers
        freeze_backbone: freeze backbone during initial training phase

    Returns:
        Compiled Keras model
    """
    # ── Input ─────────────────────────────────────────────────────────────────
    inputs = keras.Input(shape=image_shape, name="image_input")

    # ── Preprocessing ──────────────────────────────────────────────────────────
    # EfficientNetV2S expects values in [-1, 1] via preprocess_input
    x = layers.Lambda(
        lambda img: preprocess_input(img),
        name="efficientnet_preprocessing"
    )(inputs)

    # ── EfficientNetV2-S backbone ──────────────────────────────────────────────
    backbone = EfficientNetV2S(
        include_top=False,
        weights="imagenet",
        input_tensor=x,
        pooling=None,
    )
    backbone.trainable = not freeze_backbone

    # ── Feature extraction head ────────────────────────────────────────────────
    x = backbone.output

    # Global average pooling
    x = layers.GlobalAveragePooling2D(name="gap")(x)

    # Dense block 1
    x = layers.Dense(
        512,
        activation="relu",
        kernel_regularizer=regularizers.l2(l2_reg),
        name="dense_512",
    )(x)
    x = layers.BatchNormalization(name="bn_512")(x)
    x = layers.Dropout(dropout_rate, name="dropout_1")(x)

    # Dense block 2
    x = layers.Dense(
        256,
        activation="relu",
        kernel_regularizer=regularizers.l2(l2_reg),
        name="dense_256",
    )(x)
    x = layers.BatchNormalization(name="bn_256")(x)
    x = layers.Dropout(dropout_rate * 0.75, name="dropout_2")(x)

    # Output — softmax over crime classes
    outputs = layers.Dense(
        num_classes,
        activation="softmax",
        kernel_regularizer=regularizers.l2(l2_reg),
        name="crime_output",
    )(x)

    model = keras.Model(inputs=backbone.input, outputs=outputs, name="CrimeCNN")

    _compile(model)
    return model


def _compile(model: keras.Model, learning_rate: float = 1e-4):
    """Compile model with Adam + label-smoothing cross-entropy."""
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=learning_rate),
        loss=keras.losses.CategoricalCrossentropy(label_smoothing=0.1),
        metrics=[
            keras.metrics.CategoricalAccuracy(name="accuracy"),
            keras.metrics.TopKCategoricalAccuracy(k=3, name="top3_accuracy"),
        ],
    )


def unfreeze_top_layers(model: keras.Model, n_layers: int = 20,
                         learning_rate: float = 1e-5):
    """
    Unfreeze top N backbone layers for fine-tuning phase.
    Call this after initial training with frozen backbone.
    """
    backbone = model.get_layer("efficientnetv2-s")
    backbone.trainable = True
    for layer in backbone.layers[:-n_layers]:
        layer.trainable = False
    _compile(model, learning_rate=learning_rate)
    print(f"Unfroze top {n_layers} backbone layers. LR set to {learning_rate}")


# =============================================================================
#  Inference helpers
# =============================================================================

def preprocess_image(image_path: str) -> np.ndarray:
    """
    Load and preprocess a single image for inference.
    Returns array of shape (1, 224, 224, 3) with float32 pixels.
    """
    img = keras.utils.load_img(image_path, target_size=IMAGE_SIZE)
    arr = keras.utils.img_to_array(img)          # (224,224,3) float32
    arr = np.expand_dims(arr, axis=0)             # (1,224,224,3)
    return arr   # preprocess_input called inside model Lambda layer


def predict_crime(
    model: keras.Model,
    image_path: str,
) -> dict:
    """
    Run CNN inference on a single image.

    Returns:
        {
          "crime":         str,   top predicted crime class
          "probability":   float, softmax probability (0-1)
          "confidence_pct":float, probability as percentage
          "below_threshold": bool,
          "all_probs":     {crime: prob},
        }
    """
    arr   = preprocess_image(image_path)
    probs = model.predict(arr, verbose=0)[0]      # shape (NUM_CLASSES,)

    idx      = int(np.argmax(probs))
    top_prob = float(probs[idx])
    crime    = CRIME_CLASSES[idx]

    all_probs = {
        CRIME_CLASSES[i]: round(float(probs[i]), 4)
        for i in range(NUM_CLASSES)
    }

    return {
        "crime":            crime,
        "probability":      round(top_prob, 4),
        "confidence_pct":   round(top_prob * 100, 1),
        "below_threshold":  top_prob < CNN_CONFIDENCE_THRESHOLD,
        "all_probs":        all_probs,
        "top3": [
            {"crime": CRIME_CLASSES[i], "prob": round(float(probs[i]), 4)}
            for i in np.argsort(probs)[::-1][:3]
        ],
    }


# =============================================================================
#  Save / load
# =============================================================================

MODEL_SAVE_PATH = "models/crime_cnn.keras"
WEIGHTS_PATH    = "models/crime_cnn_weights.h5"


def save_model(model: keras.Model, path: str = MODEL_SAVE_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    model.save(path)
    print(f"Model saved → {path}")


def load_model(path: str = MODEL_SAVE_PATH) -> keras.Model:
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Model not found at {path}. Run train_crime_model.py first."
        )
    model = keras.models.load_model(path)
    print(f"Model loaded ← {path}")
    return model


def save_class_names(path: str = "models/class_names.txt"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("\n".join(CRIME_CLASSES))
    print(f"Class names saved → {path}")


def load_class_names(path: str = "models/class_names.txt") -> list:
    if not os.path.exists(path):
        return CRIME_CLASSES
    with open(path) as f:
        return [l.strip() for l in f if l.strip()]


# =============================================================================
#  Quick summary
# =============================================================================

if __name__ == "__main__":
    model = build_model()
    model.summary()
    print(f"\nCrime classes ({NUM_CLASSES}):")
    for i, c in enumerate(CRIME_CLASSES):
        print(f"  {i:2d}. {c}")
