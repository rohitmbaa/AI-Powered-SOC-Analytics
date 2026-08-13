
import pandas as pd

AUTH = "../data/raw/authentication_logs.csv"
FIREWALL = "../data/raw/firewall_logs.csv"
ENDPOINT = "../data/raw/endpoint_logs.csv"

def detect_bruteforce(auth, threshold=10, window_minutes=5):
    a = auth.sort_values("timestamp").copy()
    failures = a[a["login_status"].eq("Failure")]
    results = []
    for (user, source_ip), g in failures.groupby(["user", "source_ip"]):
        g = g.sort_values("timestamp")
        for i, row in g.iterrows():
            window_end = row["timestamp"] + pd.Timedelta(minutes=window_minutes)
            count = ((g["timestamp"] >= row["timestamp"]) & (g["timestamp"] <= window_end)).sum()
            if count > threshold:
                success_after = a[
                    (a["user"].eq(user)) &
                    (a["source_ip"].eq(source_ip)) &
                    (a["timestamp"] > row["timestamp"]) &
                    (a["timestamp"] <= window_end) &
                    (a["login_status"].eq("Success"))
                ]
                if not success_after.empty:
                    results.append({
                        "detection_rule": "Brute Force + Successful Login",
                        "severity": "High",
                        "user": user,
                        "source_ip": source_ip,
                        "first_seen": row["timestamp"],
                        "evidence_count": int(count)
                    })
                    break
    return pd.DataFrame(results).drop_duplicates()

def detect_suspicious_powershell(endpoint):
    e = endpoint[endpoint["process"].str.lower().eq("powershell.exe")].copy()
    e["suspicious"] = e["command_line"].str.contains(
        "EncodedCommand|encodedcommand", case=False, regex=True, na=False
    )
    e = e[e["suspicious"]]
    return e[["event_id","timestamp","user","host","command_line"]].assign(
        detection_rule="Suspicious PowerShell",
        severity="High"
    )

def detect_large_outbound(firewall, threshold_bytes=500_000_000):
    f = firewall[firewall["bytes_out"].ge(threshold_bytes)].copy()
    return f.assign(
        detection_rule="Abnormal Outbound Transfer",
        severity="High"
    )[["event_id","timestamp","source_ip","destination_ip","bytes_out",
       "detection_rule","severity"]]

if __name__ == "__main__":
    auth = pd.read_csv(AUTH, parse_dates=["timestamp"])
    fw = pd.read_csv(FIREWALL, parse_dates=["timestamp"])
    ep = pd.read_csv(ENDPOINT, parse_dates=["timestamp"])

    brute = detect_bruteforce(auth)
    powershell = detect_suspicious_powershell(ep)
    exfil = detect_large_outbound(fw)

    print("Brute-force detections:", len(brute))
    print("Suspicious PowerShell detections:", len(powershell))
    print("Large outbound transfer detections:", len(exfil))

    brute.to_csv("../data/processed/detected_bruteforce.csv", index=False)
    powershell.to_csv("../data/processed/detected_powershell.csv", index=False)
    exfil.to_csv("../data/processed/detected_exfiltration.csv", index=False)
