from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--incidents", required=True)
    parser.add_argument("--truth", required=True)
    args = parser.parse_args()
    incidents = json.loads(Path(args.incidents).read_text(encoding="utf-8"))
    with Path(args.truth).open(encoding="utf-8", newline="") as fh:
        labels = {row["event_id"]: int(row["is_malicious"]) for row in csv.DictReader(fh)}
    predicted = {event_id: 0 for event_id in labels}
    for incident in incidents:
        positive = int(incident["risk_score"] >= 65)
        for event_id in incident["event_ids"]:
            if event_id in predicted:
                predicted[event_id] = max(predicted[event_id], positive)
    tp = sum(labels[k] == 1 and predicted[k] == 1 for k in labels)
    fp = sum(labels[k] == 0 and predicted[k] == 1 for k in labels)
    tn = sum(labels[k] == 0 and predicted[k] == 0 for k in labels)
    fn = sum(labels[k] == 1 and predicted[k] == 0 for k in labels)
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    print(json.dumps({"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3)}, indent=2))


if __name__ == "__main__":
    main()
