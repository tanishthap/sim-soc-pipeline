from __future__ import annotations

import argparse
from pathlib import Path

from soc_pipeline.pipeline import run_pipeline


def main() -> None:
    project_root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Run the simulated SOC detection pipeline.")
    parser.add_argument(
        "--input",
        default=str(project_root / "data" / "sample_logs.csv"),
        help="Path to a structured CSV log dataset.",
    )
    parser.add_argument(
        "--out",
        default=str(project_root / "reports"),
        help="Directory where alert and report outputs should be written.",
    )
    args = parser.parse_args()

    alerts = run_pipeline(args.input, args.out)
    print(f"Processed logs and generated {len(alerts)} alerts.")
    for alert in alerts:
        print(
            f"{alert.priority} {alert.severity.upper():8} "
            f"{alert.severity_score:3} {alert.alert_id} {alert.title}"
        )


if __name__ == "__main__":
    main()
