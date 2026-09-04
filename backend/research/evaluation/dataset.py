import json
from pathlib import Path

from research.evaluation.models import EvaluationSample


VALID_LABELS = {"benign", "qshing"}
VALID_SOURCE_TYPES = {"synthetic", "public_dataset", "real_sample", "adapted"}
VALID_SPLITS = {"development", "calibration", "test"}
REQUIRED_FIELDS = {
    "case_id",
    "label",
    "raw_qr",
    "qr_type",
    "scenario",
    "source_type",
    "source_reference",
    "attack_features",
    "encoding_features",
    "split",
    "notes",
}


class DatasetValidationError(ValueError):
    pass


def _string_tuple(value: object, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise DatasetValidationError(f"{field_name} must be a list of strings")
    return tuple(value)


def _sample_from_dict(data: object, *, line_number: int) -> EvaluationSample:
    if not isinstance(data, dict):
        raise DatasetValidationError(f"line {line_number}: sample must be an object")
    missing = REQUIRED_FIELDS.difference(data)
    if missing:
        raise DatasetValidationError(
            f"line {line_number}: missing fields: {', '.join(sorted(missing))}"
        )

    for name in ("case_id", "label", "raw_qr", "qr_type", "scenario", "source_type", "split"):
        if not isinstance(data[name], str) or not data[name]:
            raise DatasetValidationError(f"line {line_number}: {name} must be a non-empty string")

    if data["label"] not in VALID_LABELS:
        raise DatasetValidationError(f"line {line_number}: invalid label {data['label']!r}")
    if data["source_type"] not in VALID_SOURCE_TYPES:
        raise DatasetValidationError(
            f"line {line_number}: invalid source_type {data['source_type']!r}"
        )
    if data["split"] not in VALID_SPLITS:
        raise DatasetValidationError(f"line {line_number}: invalid split {data['split']!r}")

    for optional_name in ("source_reference", "notes"):
        if data[optional_name] is not None and not isinstance(data[optional_name], str):
            raise DatasetValidationError(
                f"line {line_number}: {optional_name} must be a string or null"
            )

    return EvaluationSample(
        case_id=data["case_id"],
        label=data["label"],
        raw_qr=data["raw_qr"],
        qr_type=data["qr_type"],
        scenario=data["scenario"],
        source_type=data["source_type"],
        source_reference=data["source_reference"],
        attack_features=_string_tuple(data["attack_features"], "attack_features"),
        encoding_features=_string_tuple(data["encoding_features"], "encoding_features"),
        split=data["split"],
        notes=data["notes"],
    )


def load_dataset(path: str | Path, *, split: str | None = None) -> list[EvaluationSample]:
    if split is not None and split not in VALID_SPLITS:
        raise DatasetValidationError(f"invalid requested split {split!r}")

    samples: list[EvaluationSample] = []
    seen_case_ids: set[str] = set()
    with Path(path).open("r", encoding="utf-8") as dataset_file:
        for line_number, raw_line in enumerate(dataset_file, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                raw_sample = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DatasetValidationError(
                    f"line {line_number}: invalid JSON"
                ) from exc
            sample = _sample_from_dict(raw_sample, line_number=line_number)
            if sample.case_id in seen_case_ids:
                raise DatasetValidationError(
                    f"line {line_number}: duplicate case_id {sample.case_id!r}"
                )
            seen_case_ids.add(sample.case_id)
            if split is None or sample.split == split:
                samples.append(sample)

    if not samples:
        raise DatasetValidationError("dataset contains no samples for the requested split")
    return samples

