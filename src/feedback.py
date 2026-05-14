

import os
import pandas as pd
import csv
import re


def save_feedback(anomaly, is_attack):

    feedback_path = "data/feedback.csv"
    os.makedirs("data", exist_ok=True)

    # --- FORCE clean time from anomaly source (no CSV / encoding dependency) ---
    start = anomaly.get("start_time")
    end = anomaly.get("end_time")

    if start and end:
        clean_time = f"{start} -> {end}"
        print("DEBUG TIME (STRUCTURED):", clean_time)
    else:
        # Fallback: extract from raw string ONLY if needed
        raw_time = anomaly.get("time")
        clean_time = "Unknown"

        if raw_time:
            matches = re.findall(r"\d{2}:\d{2}:\d{2}", str(raw_time))
            if len(matches) >= 2:
                clean_time = f"{matches[0]} -> {matches[1]}"
                print("DEBUG TIME (REGEX):", clean_time)
            elif len(matches) == 1:
                clean_time = matches[0]
                print("DEBUG TIME (SINGLE):", clean_time)

    row = {
        "time": clean_time,
        "requests": anomaly.get("requests"),
        "pattern": anomaly.get("pattern"),
        "similarity": anomaly.get("similarity"),
        "confirmed": is_attack
    }

    df_new = pd.DataFrame([row])

    if os.path.exists(feedback_path):
        df_existing = pd.read_csv(
            feedback_path,
            encoding="utf-8-sig",
            engine="python"
        )
        df_new = pd.concat([df_existing, df_new], ignore_index=True)

    df_new.to_csv(
        feedback_path,
        index=False,
        quoting=csv.QUOTE_ALL,
        encoding="utf-8-sig"
    )