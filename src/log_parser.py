from sklearn.ensemble import IsolationForest
import pandas as pd

def extract_ip(line):

    parts = line.split()

    if len(parts) == 0:

        return None

    return parts[0]

# Extract timestamp from a log line

def extract_timestamp(line):

    parts = line.split("[")

    if len(parts) > 1:

        timestamp_part = parts[1].split("]")[0]

        # Remove timezone (e.g. +0000) and keep full timestamp
        timestamp_part = timestamp_part.split(" ")[0].strip()

        if len(timestamp_part) < 19:
            return None

        return timestamp_part

    return None

def read_logs(file_path=None, file_content=None):

    import os
    import pandas as pd

    history_path = "data/history.csv"

    ip_time_counts = {}

    ip_totals = {}

    time_counts = {}

    pattern_colors = {
        "Burst Attack": "#DC2626",
        "Sustained Attack": "#F59E0B",
        "Slow Build Attack": "#3B82F6",
        "Decay Attack": "#10B981",
        "Wave Attack": "#8B5CF6",
        "Unknown": "#6B7280"
    }

    df_anom = pd.DataFrame()

    if file_content is not None:

        lines = file_content.decode("utf-8").splitlines()

    else:

        with open(file_path, "r") as file:

            lines = file.readlines()

    for line in lines:

        if not line.strip():
            continue

        ip = extract_ip(line)
        timestamp = extract_timestamp(line)

        if ip is None or timestamp is None:
            continue

        # --- FIX: Normalize timestamp to minute-level (HH:MM) ---
        try:
            ts_parsed = pd.to_datetime(timestamp, format="%d/%b/%Y:%H:%M:%S")
            time_bucket = ts_parsed.strftime("%H:%M")
        except Exception as e:
            print("Error in log_parser:", e)
            continue

        key = (ip, time_bucket)

        if key in ip_time_counts:
            ip_time_counts[key] += 1
        else:
            ip_time_counts[key] = 1

        # total requests per IP
        if ip in ip_totals:
            ip_totals[ip] += 1
        else:
            ip_totals[ip] = 1

        # ✅ NEW: total requests per time_bucket
        if time_bucket in time_counts:
            time_counts[time_bucket] += 1
        else:
            time_counts[time_bucket] = 1

    THRESHOLD = 3

    HIGH_THRESHOLD = 5

    alerts = []

    normal_activity = []

    for (ip, time_bucket), count in sorted(ip_time_counts.items(), key=lambda x: x[1], reverse=True):
        entry = {
            "ip": ip,
            "timestamp": time_bucket,
            "count": count
        }
        if count >= HIGH_THRESHOLD:
            entry["level"] = "high"
            alerts.append(entry)
        elif count >= THRESHOLD:
            entry["level"] = "medium"
            alerts.append(entry)
        else:
            entry["level"] = "normal"
            normal_activity.append(entry)

    anomalies = []

    try:
        # --- Baseline statistics for dynamic severity ---
        request_values = list(time_counts.values())

        if request_values:
            avg_requests = sum(request_values) / len(request_values)
            variance = sum((x - avg_requests) ** 2 for x in request_values) / len(request_values)
            std_requests = variance ** 0.5
        else:
            avg_requests = 0
            std_requests = 0

        if time_counts:
            df_time = pd.DataFrame(list(time_counts.items()), columns=["Time", "Requests"])

            # --- Load historical baseline ---
            if os.path.exists(history_path):
                df_history = pd.read_csv(history_path)

                if "Requests" in df_history.columns:
                    global_avg = df_history["Requests"].mean()
                    global_std = df_history["Requests"].std()
                else:
                    global_avg = df_time["Requests"].mean()
                    global_std = df_time["Requests"].std()
            else:
                global_avg = df_time["Requests"].mean()
                global_std = df_time["Requests"].std()

            # Keep original string and create parsed column safely
            df_time["TimeStr"] = df_time["Time"].astype(str)
            df_time["TimeParsed"] = pd.to_datetime(
                df_time["TimeStr"],
                format="%H:%M",
                errors="coerce"
            )
            df_time["TimeOnly"] = df_time["TimeParsed"].dt.strftime("%H:%M")

            # Sort by parsed time where available
            if not df_time["TimeParsed"].isna().all():
                df_time = df_time.sort_values(by="TimeParsed")

            # --- Enhanced ML Features ---
            # Rolling average (baseline smoothing)
            df_time["RollingMean"] = df_time["Requests"].rolling(window=3, min_periods=1).mean()

            # Change in traffic (velocity)
            df_time["Delta"] = df_time["Requests"].diff().fillna(0)

            # Absolute change (magnitude of spike)
            df_time["DeltaAbs"] = df_time["Delta"].abs()

            # Add relative deviation (stronger anomaly signal)
            df_time["RelDev"] = (df_time["Requests"] - df_time["RollingMean"]).abs()

            # --- FIX: Use adaptive (blended) baseline for Z-Score ---
            if std_requests is None or std_requests == 0:
                std_requests = 1

            # --- Leave-One-Out Z-Score (prevents anomaly dilution) ---
            z_scores = []
            values = df_time["Requests"].tolist()

            for i, val in enumerate(values):
                others = values[:i] + values[i+1:]

                if len(others) > 1:
                    mean_others = sum(others) / len(others)
                    var_others = sum((x - mean_others) ** 2 for x in others) / len(others)
                    std_others = var_others ** 0.5
                else:
                    mean_others = avg_requests
                    std_others = std_requests

                if std_others == 0:
                    std_others = 1

                z = (val - mean_others) / std_others
                z_scores.append(z)

            df_time["ZScore"] = z_scores

            # Prepare ML feature set
            X = df_time[["Requests", "RollingMean", "DeltaAbs", "RelDev"]]

            # Handle any missing values
            X = X.fillna(0)

            # --- FIX: Adaptive baseline (blend current + historical) ---
            current_avg = df_time["Requests"].mean()
            current_std = df_time["Requests"].std()

            # Handle edge cases
            if pd.isna(current_std):
                current_std = 0
            if pd.isna(global_std):
                global_std = current_std

            # Blend (70% current, 30% historical)
            avg_requests = (0.7 * current_avg) + (0.3 * global_avg)
            std_requests = (0.7 * current_std) + (0.3 * global_std)

            # Train Isolation Forest
            # Increased sensitivity for real-world detection
            model = IsolationForest(contamination=0.2, random_state=42)
            df_time["anomaly"] = model.fit_predict(X)

            # --- Hybrid Detection (ML + Statistical + Heuristic) ---
            anomaly_rows = df_time[df_time["anomaly"] == -1].copy()

            # Statistical anomalies (Z-score based)
            Z_THRESHOLD = 1.0
            stat_anomalies = df_time[df_time["ZScore"].abs() > Z_THRESHOLD]

            # Sudden spikes (velocity-based)

            spike_anomalies = df_time[df_time["DeltaAbs"] > std_requests]
            # Combine all sources
            anomaly_rows = pd.concat([anomaly_rows, stat_anomalies, spike_anomalies]).drop_duplicates()

            # --- KILL NOISE: remove low-value anomalies (stronger filter) ---
            anomaly_rows = anomaly_rows[
                (anomaly_rows["Requests"] > avg_requests) &
                (anomaly_rows["Requests"] > (avg_requests + 0.3 * std_requests))
            ]

            # --- Fallback detection if ML finds nothing ---
            if anomaly_rows.empty and len(df_time) > 2:
                for i, row in df_time.iterrows():
                    req = row["Requests"]

                    # simple spike rule
                    if req > avg_requests + std_requests and req > avg_requests:
                        anomaly_rows = pd.concat([anomaly_rows, row.to_frame().T])

            # --- Final fallback: only pick peak if it is above baseline ---
            if anomaly_rows.empty and not df_time.empty:
                peak_row = df_time.loc[df_time["Requests"].idxmax()]
                if peak_row["Requests"] > avg_requests:
                    anomaly_rows = pd.DataFrame([peak_row])

            for _, row in anomaly_rows.iterrows():
                # Prefer parsed time; fallback to raw string (extract HH:MM)
                if "TimeParsed" in row and pd.notna(row.get("TimeParsed")):
                    time_str = row["TimeParsed"].strftime("%H:%M")
                else:
                    raw = str(row.get("TimeStr", row.get("Time")))
                    try:
                        parsed = pd.to_datetime(raw, format="%d/%b/%Y:%H:%M:%S", errors="coerce")
                        time_str = parsed.strftime("%H:%M") if pd.notna(parsed) else raw
                    except:
                        time_str = raw

                req = int(row["Requests"])

                # --- FINAL NOISE GUARD ---
                if req <= avg_requests:
                    continue


                # --- Enhanced Attack Pattern Detection (multi-pattern + learning ready) ---
                pattern = "Unknown"

                try:
                    current_index = row.name

                    # Window for behavioural analysis
                    start_idx = max(current_index - 3, 0)
                    end_idx = min(current_index + 4, len(df_time))
                    window = df_time.iloc[start_idx:end_idx]["Requests"]

                    prev_req = df_time.iloc[current_index - 1]["Requests"] if current_index > 0 else req

                    deviation = req - avg_requests

                    # --- Burst Attack ---
                    if req > prev_req * 1.5 and deviation > (0.6 * std_requests):
                        pattern = "Burst Attack"

                    # --- Sustained Attack (FIXED - stronger detection) ---
                    elif len(window) >= 3 and sum(window > avg_requests) >= 3:
                        pattern = "Sustained Attack"

                    # --- Slow Build Attack ---
                    elif len(window) >= 3 and all(x <= y for x, y in zip(window, window[1:])) and window.iloc[-1] > avg_requests:
                        pattern = "Slow Build Attack"

                    # --- Decay Attack ---
                    elif len(window) >= 3 and all(x >= y for x, y in zip(window, window[1:])) and window.iloc[0] > avg_requests:
                        pattern = "Decay Attack"

                    # --- Wave Attack ---
                    else:
                        diffs = window.diff().fillna(0)
                        sign_changes = sum((diffs.iloc[i] * diffs.iloc[i+1] < 0) for i in range(len(diffs)-1))

                        if sign_changes >= 2 and (window.max() - window.min()) > std_requests:
                            pattern = "Wave Attack"

                except Exception:
                    pattern = "Unknown"

                # --- Continuation detection ---
                is_continuation = False
                if current_index > 0:
                    prev_req_cont = df_time.iloc[current_index - 1]["Requests"]
                    if req == prev_req_cont and req > avg_requests:
                        is_continuation = True

                # --- Refined Severity Scaling (pattern + intensity + z-score) ---
                z_val = abs(float(row.get("ZScore", 0)))

                if pattern == "Burst Attack":
                    if z_val > 1.5 or req > avg_requests + std_requests:
                        severity = "HIGH"
                    else:
                        severity = "MEDIUM"

                elif pattern == "Sustained Attack":
                    if z_val > 1.2 and req > avg_requests + (0.5 * std_requests):
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"

                else:
                    if z_val > 2 or req > avg_requests + (1.5 * std_requests):
                        severity = "HIGH"
                    elif z_val > 1 or req > avg_requests + (0.8 * std_requests):
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"

                # --- Reason weighting (for explanation layer) ---
                if pattern in ["Burst Attack", "Wave Attack"]:
                    detection_basis = "Behavioural dominance"
                elif z_val > 1.5:
                    detection_basis = "Statistical dominance"
                else:
                    detection_basis = "Hybrid detection"

                # --- Refined Confidence Score (aligned with severity + behaviour) ---
                z_val = abs(float(row.get("ZScore", 0)))
                deviation_ratio = (req - avg_requests) / (std_requests if std_requests > 0 else 1)

                z_component = min(z_val / 2, 1)
                dev_component = min(deviation_ratio / 2, 1)

                base_confidence = (0.6 * z_component + 0.4 * dev_component)

                # --- Boost confidence based on pattern + severity ---
                pattern_boost = 0
                if pattern == "Burst Attack":
                    pattern_boost = 0.2
                elif pattern == "Sustained Attack":
                    pattern_boost = 0.1

                severity_boost = 0
                if severity == "HIGH":
                    severity_boost = 0.2
                elif severity == "MEDIUM":
                    severity_boost = 0.1

                raw_conf = base_confidence + pattern_boost + severity_boost

                # --- Apply soft cap to avoid unrealistic certainty ---
                if pattern == "Burst Attack":
                    max_cap = 0.9
                elif pattern == "Sustained Attack":
                    max_cap = 0.8
                else:
                    max_cap = 0.75

                confidence = int(min(raw_conf, max_cap) * 100)
                confidence = max(10, confidence)

                # --- Anomaly Score (% above baseline) ---
                if avg_requests > 0:
                    score = round(((req - avg_requests) / avg_requests) * 100, 1)
                else:
                    score = 0

                # --- Smarter Similarity Scoring (multi-feature + feedback learning) ---
                similarity_score = 0
                try:
                    if os.path.exists(history_path):
                        df_hist = pd.read_csv(history_path)

                        if not df_hist.empty and all(col in df_hist.columns for col in ["Requests", "Delta", "RelDev"]):

                            current_req = req
                            current_delta = row.get("Delta", 0)
                            current_dev = row.get("RelDev", 0)

                            similarities = []

                            for _, hist_row in df_hist.iterrows():
                                req_diff = abs(hist_row["Requests"] - current_req)
                                delta_diff = abs(hist_row["Delta"] - current_delta)
                                dev_diff = abs(hist_row["RelDev"] - current_dev)

                                req_score = max(0, 1 - (req_diff / (current_req + 1)))
                                delta_score = max(0, 1 - (delta_diff / (abs(current_delta) + 1)))
                                dev_score = max(0, 1 - (dev_diff / (abs(current_dev) + 1)))

                                combined_score = (
                                    0.5 * req_score +
                                    0.3 * delta_score +
                                    0.2 * dev_score
                                )

                                similarities.append(combined_score)

                            if similarities:
                                similarity_score = int(max(similarities) * 100)

                    # --- Feedback Learning Boost ---
                    feedback_path = "data/feedback.csv"

                    if os.path.exists(feedback_path):
                        df_feedback = pd.read_csv(feedback_path)

                        if not df_feedback.empty:

                            confirmed_attacks = df_feedback[df_feedback["confirmed"] == True]

                            for _, fb in confirmed_attacks.iterrows():
                                fb_req = fb.get("requests", 0)
                                fb_pattern = fb.get("pattern", "")

                                if abs(fb_req - current_req) <= 2:
                                    similarity_score = min(similarity_score + 15, 100)

                                # Boost if pattern matches
                                if fb_pattern == pattern:
                                    similarity_score = min(similarity_score + 10, 100)

                            false_positives = df_feedback[df_feedback["confirmed"] == False]

                            for _, fb in false_positives.iterrows():
                                fb_req = fb.get("requests", 0)
                                fb_pattern = fb.get("pattern", "")

                                if abs(fb_req - current_req) <= 2:
                                    similarity_score = max(similarity_score - 15, 0)

                                # Penalise matching false pattern
                                if fb_pattern == pattern:
                                    similarity_score = max(similarity_score - 10, 0)

                except Exception:
                    similarity_score = 0

                # --- Ensure correct request count from df_time ---
                true_req = int(df_time.loc[row.name, "Requests"])

                anomalies.append({
                    "time": time_str,
                    "start_time": time_str,
                    "end_time": time_str,
                    "requests": true_req,
                    "severity": severity,
                    "score": score,
                    "pattern": pattern,
                    "similarity": similarity_score,
                    "z_score": round(float(row.get("ZScore", 0)), 2),
                    "confidence": confidence,
                    "idx": row.name,
                    "detection_basis": detection_basis,
                    "is_continuation": is_continuation
                })

                # --- Add contextual data (top IPs contributing to this time) ---
                contributing_ips = []

                for (ip_key, ts_key), count in ip_time_counts.items():
                    ts_formatted = ts_key
                    if ts_formatted == time_str:
                        contributing_ips.append({"ip": ip_key, "count": count})

                # Sort top contributors
                contributing_ips = sorted(contributing_ips, key=lambda x: x["count"], reverse=True)[:3]

                anomalies[-1]["top_ips"] = contributing_ips

            # --- EVENT GROUPING: merge nearby anomalies into single events ---
            grouped_anomalies = []

            if anomalies:
                # --- Build reliable lookup: TimeOnly -> Requests ---
                time_lookup = {}
                if 'TimeOnly' in df_time.columns:
                    for _, r in df_time.iterrows():
                        t_only = r.get('TimeOnly')
                        if pd.notna(t_only):
                            time_lookup[str(t_only)] = int(r.get('Requests', 0))

                # Sort using actual datetime for correct ordering
                from datetime import datetime
                anomalies_sorted = sorted(anomalies, key=lambda x: datetime.strptime(x["time"], "%H:%M"))

                current_group = [anomalies_sorted[0]]

                for i in range(1, len(anomalies_sorted)):
                    prev = current_group[-1]
                    curr = anomalies_sorted[i]

                    # Convert time to seconds for comparison
                    from datetime import datetime
                    t_prev = datetime.strptime(prev["time"], "%H:%M")
                    t_curr = datetime.strptime(curr["time"], "%H:%M")

                    time_diff = (t_curr - t_prev).total_seconds()

                    # Group contiguous minutes (<= 60 seconds difference)
                    if time_diff <= 60:
                        current_group.append(curr)
                    else:
                        grouped_anomalies.append(current_group)
                        current_group = [curr]

                grouped_anomalies.append(current_group)

                # Merge groups into single events
                merged = []

                for group in grouped_anomalies:
                    peak = max(group, key=lambda x: x["requests"])

                    # --- TRUE aggregation using TimeOnly lookup (index-free) ---
                    times_in_group = [g.get('time') for g in group if g.get('time')]

                    vals = []
                    for t in times_in_group:
                        try:
                            parts = str(t).split(":")
                            if len(parts) >= 2:
                                hh, mm = parts[-2], parts[-1]
                                t_key = f"{hh}:{mm}"
                            else:
                                t_key = str(t)

                            v = time_lookup.get(t_key)
                            if v is not None:
                                vals.append(int(v))
                        except Exception as e:
                            print("Error in log_parser:", e)
                            continue

                    # Aggregate total requests across the full event window
                    if vals:
                        total_requests = sum(vals)
                        true_peak_req = max(vals)
                    else:
                        total_requests = int(peak.get('requests', 0))
                        true_peak_req = total_requests

                    # --- Determine dominant pattern in group ---
                    pattern_counts = {}
                    for item in group:
                        p = item.get("pattern", "Unknown")
                        pattern_counts[p] = pattern_counts.get(p, 0) + 1

                    # Select most frequent non-Unknown pattern
                    dominant_pattern = "Unknown"
                    if pattern_counts:
                        sorted_patterns = sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True)
                        for p, _ in sorted_patterns:
                            if p != "Unknown":
                                dominant_pattern = p
                                break

                        # fallback if all unknown
                        if dominant_pattern == "Unknown":
                            dominant_pattern = peak.get("pattern", "Unknown")

                    # --- Aggregate IPs across full event window ---
                    aggregated_ips = {}

                    for g in group:
                        for ip_entry in g.get("top_ips", []):
                            ip = ip_entry.get("ip")
                            count = ip_entry.get("count", 0)

                            aggregated_ips[ip] = aggregated_ips.get(ip, 0) + count

                    top_ips_combined = sorted(
                        [{"ip": ip, "count": cnt} for ip, cnt in aggregated_ips.items()],
                        key=lambda x: x["count"],
                        reverse=True
                    )[:3]

                    merged.append({
                        "time": f"{group[0]['time']} -> {group[-1]['time']}",
                        "start_time": group[0]['time'],
                        "end_time": group[-1]['time'],
                        "requests": true_peak_req,
                        "total_requests": total_requests,
                        "peak_requests": true_peak_req,
                        "event_points": len(vals) if vals else 1,
                        "severity": peak.get("severity"),
                        "score": peak.get("score"),
                        "pattern": dominant_pattern,
                        "similarity": peak.get("similarity"),
                        "confidence": peak.get("confidence", 0),
                        "z_score": peak.get("z_score", 0),
                        "top_ips": top_ips_combined
                    })

                # --- Replace raw anomalies with grouped anomalies (single source of truth) ---
                anomalies = merged

            # --- Create anomaly points dataframe for visualization ---
            anomaly_points = []

            if anomalies:
                for a in anomalies:
                    time_range = str(a.get("time", ""))

                    # Split grouped window into individual time points
                    if "->" in time_range:
                        times = [t.strip() for t in time_range.split("->")]
                    else:
                        times = [time_range]

                    for t in times:
                        try:
                            # Ensure t is formatted as HH:MM (strip whitespace)
                            t = str(t).strip()
                            # Ensure consistent HH:MM format for matching
                            t_key = t[:5]
                            match = df_time[df_time["TimeOnly"] == t_key]

                            if not match.empty:
                                req_val = int(match["Requests"].iloc[0])
                            else:
                                # DO NOT fallback to peak blindly — avoid graph distortion
                                req_val = None

                        except Exception:
                            req_val = None

                        # Only append valid aligned points
                        if req_val is not None:
                            anomaly_points.append({
                                "TimeStr": t_key,
                                "Requests": req_val,
                                "Pattern": a.get("pattern", "Unknown")
                            })

            df_anom = pd.DataFrame(anomaly_points)

    except Exception as e:
        print("Error in log_parser:", e)

    # --- Save historical data (Phase 3B) ---
    if 'df_time' in locals() and df_time is not None and not df_time.empty:
        df_save = df_time.copy()
        df_save["SessionTime"] = pd.Timestamp.now()

        os.makedirs("data", exist_ok=True)

        if os.path.exists(history_path):
            df_existing = pd.read_csv(history_path)
            df_save = pd.concat([df_existing, df_save], ignore_index=True)

        df_save.to_csv(history_path, index=False)

    return ip_totals, alerts, normal_activity, time_counts, anomalies, df_anom, pattern_colors