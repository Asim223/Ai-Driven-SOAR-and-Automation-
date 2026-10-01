from __future__ import annotations

import argparse
from pathlib import Path

from soar_lab import run_pipeline


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the AICS-112 mini-SOAR pipeline in safe dry-run mode")
    parser.add_argument("--dataset", required=True, help="Dataset folder containing events.jsonl plus a sibling common folder")
    parser.add_argument("--output", default="output", help="Output folder")
    parser.add_argument("--approval-token", default=None, help="Instructor-only simulation token; never use a production credential")
    args = parser.parse_args()
    incidents = run_pipeline(Path(args.dataset), Path(args.output), args.approval_token)
    print(f"Created {len(incidents)} candidate incident(s) in {args.output}")
    print("All actions are dry-run simulations; no real account or endpoint was changed.")


if __name__ == "__main__":
    main()
