from __future__ import annotations

import csv
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


CSV_PATH = Path(
    r"C:\Development\Git\MGS2-PS2-Textures\u - dumped from substance\mgs2_ps2_substance_version_dates.csv"
)

MAX_WORKERS = 8


def load_origin_dates(csv_path: Path) -> dict[str, float]:
    if not csv_path.is_file():
        raise SystemExit(f"CSV not found: {csv_path}")

    mapping: dict[str, float] = {}

    with csv_path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        if not reader.fieldnames or "stem" not in reader.fieldnames or "origin_date" not in reader.fieldnames:
            raise SystemExit("CSV must contain: stem, origin_date")

        for row in reader:
            stem = (row["stem"] or "").strip()
            date_raw = (row["origin_date"] or "").strip()

            if not stem or not date_raw:
                continue

            try:
                ts = float(date_raw)

                # If it's clearly milliseconds, convert to seconds
                if ts > 1e11:  # rough sanity check
                    ts = ts / 1000.0

            except ValueError:
                continue

            mapping[stem.lower()] = ts

    return mapping


def touch_file(path: Path, origin_map: dict[str, float]) -> str | None:
    key = path.stem.lower()

    ts = origin_map.get(key)
    if ts is None:
        return f"No CSV match for {path.name}"

    try:
        os.utime(path, (ts, ts))
    except Exception as e:
        return f"Failed to set timestamp for {path.name}: {e}"

    return None


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    print(f"Script dir: {script_dir}")

    origin_map = load_origin_dates(CSV_PATH)
    if not origin_map:
        raise SystemExit("CSV contained no usable timestamp mappings")

    ctxrs = list(script_dir.glob("*.ctxr"))
    if not ctxrs:
        print("No .ctxr files found")
        return

    print(f"Found {len(ctxrs)} ctxr files")
    errors: list[str] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(touch_file, p, origin_map): p for p in ctxrs}
        for f in as_completed(futures):
            result = f.result()
            if result:
                errors.append(result)

    if errors:
        print("\nCompleted with warnings:")
        for e in errors:
            print(" - " + e)
    else:
        print("All ctxr timestamps updated successfully.")


if __name__ == "__main__":
    main()
