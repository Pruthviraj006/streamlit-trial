import streamlit as st                  # Web UI framework
import pandas as pd                     # Data handling
import requests                         # API calls
import concurrent.futures               # Parallel execution
from thefuzz import fuzz                # Fuzzy matching for typosquatting
from datetime import datetime, timezone # Date calculations

# ===================== CONFIG ===================== #

OSV_API_URL = "https://api.osv.dev/v1/query"  # OSV vulnerability API

# Popular packages commonly targeted by typosquatting
TOP_PACKAGES = [
    "requests", "flask", "django", "numpy", "pandas", "scipy",
    "matplotlib", "seaborn", "sqlalchemy", "fastapi", "pytest",
    "beautifulsoup4", "pillow", "opencv-python", "tensorflow",
    "torch", "scikit-learn", "celery", "redis", "uvicorn"
]

# ===================== PARSER ===================== #

def parse_requirements(file_content):
    """Parse requirements.txt and extract (package, version)"""
    packages = []
    for line in file_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue  # Ignore comments and empty lines
        for sep in ["==", ">=", "<=", "~=", ">"]:
            if sep in line:
                name, version = line.split(sep, 1)
                packages.append((name.strip(), version.strip()))
                break
        else:
            packages.append((line, None))  # No version specified
    return packages

# ===================== OSV ENGINE ===================== #

def query_osv(package, version):
    """Query OSV API for vulnerabilities"""
    payload = {
        "package": {
            "name": package,
            "ecosystem": "PyPI"
        }
    }
    if version:
        payload["version"] = version
    try:
        r = requests.post(OSV_API_URL, json=payload, timeout=10)
        return r.json().get("vulns", []) if r.status_code == 200 else []
    except Exception:
        return []

def fetch_all_vulnerabilities(packages):
    """Fetch vulnerabilities concurrently"""
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(query_osv, pkg, ver): pkg
            for pkg, ver in packages
        }
        for future in concurrent.futures.as_completed(futures):
            results[futures[future]] = future.result()
    return results

# ===================== PYPI METADATA ===================== #

def fetch_pypi_age(package):
    """Return package age in days"""
    try:
        data = requests.get(f"https://pypi.org/pypi/{package}/json", timeout=10).json()
        upload_time = data["urls"][0]["upload_time_iso_8601"]
        upload_date = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - upload_date).days
    except Exception:
        return None

# ===================== TYPOSQUATTING ===================== #

def check_typosquatting(package):
    """Compare package name against popular ones"""
    best_score = 0
    closest = None
    for popular in TOP_PACKAGES:
        score = fuzz.ratio(package.lower(), popular.lower())
        if score > best_score:
            best_score = score
            closest = popular
    return best_score, closest

# ===================== TRUST SCORE ===================== #

def calculate_trust_score(vulns, similarity, is_new):
    """Calculate trust score"""
    score = 100
    if any("CRITICAL" in str(v.get("severity", "")) for v in vulns):
        score -= 20
    if similarity >= 90:
        score -= 50
    if is_new:
        score -= 10
    return max(score, 0)

def score_breakdown(vulns, similarity, is_new):
    """Explain why trust score was reduced"""
    reasons = []
    if any("CRITICAL" in str(v.get("severity", "")) for v in vulns):
        reasons.append("−20: Critical vulnerabilities detected")
    if similarity >= 90:
        reasons.append("−50: Looks like a typo of a popular package")
    if is_new:
        reasons.append("−10: Very new package (<30 days)")
    return reasons or ["No risk factors detected"]

# ===================== TRUST BAR ===================== #

def trust_bar(score):
    """HTML progress bar with color"""
    if score >= 80:
        color = "#22c55e"  # green
    elif score >= 60:
        color = "#eab308"  # yellow
    elif score >= 40:
        color = "#f97316"  # orange
    else:
        color = "#ef4444"  # red

    return (
        f"<div style='width:100%'>"
        f"<div style='background:#1f2937;border-radius:6px;height:12px'>"
        f"<div style='width:{score}%;background:{color};height:12px;border-radius:6px'></div>"
        f"</div>"
        f"<div style='font-size:12px;text-align:right;color:#9ca3af'>{score}%</div>"
        f"</div>"
    )

# ===================== UI ===================== #

st.set_page_config(page_title="Supply Chain Sentinel", layout="wide")
st.title("🛡️ Supply Chain Sentinel")
st.caption("Dependency vulnerability & typosquatting risk analyzer")

uploaded_file = st.file_uploader("Upload requirements.txt", type="txt")

if uploaded_file:
    packages = parse_requirements(uploaded_file.read().decode("utf-8"))
    st.success(f"Parsed {len(packages)} packages")

    vuln_data = fetch_all_vulnerabilities(packages)

    rows = []
    for pkg, ver in packages:
        vulns = vuln_data.get(pkg, [])
        age = fetch_pypi_age(pkg)
        similarity, target = check_typosquatting(pkg)
        is_new = age is not None and age < 30
        score = calculate_trust_score(vulns, similarity, is_new)

        rows.append({
            "Package": pkg,
            "Version": ver or "Any",
            "Vulnerabilities": len(vulns),
            "Similarity %": similarity,
            "Closest Popular Package": target,
            "Package Age (days)": age,
            "Trust Score": score,
            "Trust Score Bar": trust_bar(score),
            "Score Explanation": "<br>".join(score_breakdown(vulns, similarity, is_new))
        })

    df = pd.DataFrame(rows)

    # ===================== OVERALL RISK ===================== #

    st.subheader("📊 Overall Risk Distribution")

    safe = (df["Trust Score"] >= 80).sum()
    review = ((df["Trust Score"] >= 60) & (df["Trust Score"] < 80)).sum()
    risky = ((df["Trust Score"] >= 40) & (df["Trust Score"] < 60)).sum()
    danger = (df["Trust Score"] < 40).sum()
    total = len(df)

    st.markdown(f"""
    <div style="display:flex;height:18px;border-radius:6px;overflow:hidden">
      <div style="width:{safe/total*100}%;background:#22c55e"></div>
      <div style="width:{review/total*100}%;background:#eab308"></div>
      <div style="width:{risky/total*100}%;background:#f97316"></div>
      <div style="width:{danger/total*100}%;background:#ef4444"></div>
    </div>
    <small>🟢 Safe: {safe} | 🟡 Review: {review} | 🟠 Risky: {risky} | 🔴 Dangerous: {danger}</small>
    """, unsafe_allow_html=True)

    # ===================== TABLE ===================== #

    st.subheader("📦 Package Risk Table")

    display_df = df.drop(columns=["Trust Score"])

    st.markdown("""
    <style>
    th, td { padding: 10px; vertical-align: middle; }
    td:last-child { min-width: 160px; }
    </style>
    """, unsafe_allow_html=True)

    st.markdown(display_df.to_html(escape=False, index=False), unsafe_allow_html=True)

    # ===================== CVE DETAILS ===================== #

    st.subheader("🔍 Vulnerability Details")

    for _, row in df.iterrows():
        if row["Vulnerabilities"] == 0:
            continue
        with st.expander(f"{row['Package']} — {row['Vulnerabilities']} vulnerabilities"):
            for v in vuln_data.get(row["Package"], []):
                st.markdown(f"**{v.get('id','N/A')}** — {v.get('summary','No description')}")

    # ===================== SCORE EXPLANATION ===================== #

    st.subheader("📉 Trust Score Deductions")

    for _, row in df.iterrows():
        with st.expander(f"{row['Package']} — Trust Score {row['Trust Score']}"):
            st.markdown(row["Score Explanation"], unsafe_allow_html=True)

    # ===================== EXPORT ===================== #

    st.subheader("📤 Export Security Report")

    export_df = df.drop(columns=["Trust Score Bar"])

    col1, col2 = st.columns(2)

    with col1:
        st.download_button(
            "⬇ Download CSV",
            export_df.to_csv(index=False).encode("utf-8"),
            "supply_chain_report.csv",
            "text/csv"
        )

    with col2:
        st.download_button(
            "⬇ Download JSON",
            export_df.to_json(orient="records", indent=2).encode("utf-8"),
            "supply_chain_report.json",
            "application/json"
        )
