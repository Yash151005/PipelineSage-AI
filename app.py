import os
import re
import json
import requests
import streamlit as st
from datetime import datetime

st.set_page_config(page_title="PipelineSage AI", page_icon="🛡️", layout="wide")

# PipelineSage AI — single-file Streamlit MVP
# Configure secrets in .streamlit/secrets.toml or environment variables.
GITLAB_URL = st.secrets.get("GITLAB_URL", os.getenv("GITLAB_URL", "https://gitlab.com"))
GITLAB_TOKEN = st.secrets.get("GITLAB_TOKEN", os.getenv("GITLAB_TOKEN", ""))
GITLAB_PROJECT_ID = st.secrets.get("GITLAB_PROJECT_ID", os.getenv("GITLAB_PROJECT_ID", ""))
OPENAI_API_KEY = st.secrets.get("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY", ""))
OPENAI_BASE_URL = st.secrets.get("OPENAI_BASE_URL", os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"))
OPENAI_MODEL = st.secrets.get("OPENAI_MODEL", os.getenv("OPENAI_MODEL", "gpt-4o-mini"))

BG = "#0b1020"
st.markdown("""
<style>
.stApp { background: radial-gradient(circle at 85% 5%, #1a1741 0, #0b1020 42%, #080c18 100%); color:#f3f5ff; }
.block-container { padding-top: 1.6rem; max-width: 1400px; }
.hero { padding: 1.5rem 1.7rem; border: 1px solid #30385c; border-radius: 20px;
background: linear-gradient(120deg, rgba(124,58,237,.18), rgba(14,165,233,.08)); }
.eyebrow { color:#67e8f9; font-size:.78rem; letter-spacing:.15em; font-weight:800; }
.hero h1 { font-size:2.65rem; margin:.25rem 0 .1rem; color:#f8fafc; }
.hero p { color:#b7c2df; font-size:1.05rem; margin:.25rem 0; }
.metric { background:#121a31; border:1px solid #2b3657; border-radius:14px; padding:1rem; min-height:105px; }
.metric-label { color:#a8b4d4; font-size:.82rem; }
.metric-value { color:#f8fafc; font-size:1.55rem; font-weight:800; }
.pill { display:inline-block; border:1px solid #47517a; border-radius:999px; padding:.28rem .65rem;
color:#dce5ff; font-size:.78rem; margin:.2rem .25rem .2rem 0; }
div[data-testid="stTabs"] button { font-weight:700; }
.stButton button { border-radius:10px; font-weight:700; }
small, .muted { color:#a8b4d4; }
</style>
""", unsafe_allow_html=True)

def metric(label, value, hint=""):
    st.markdown(f'<div class="metric"><div class="metric-label">{label}</div><div class="metric-value">{value}</div><div class="metric-label">{hint}</div></div>', unsafe_allow_html=True)

def analyze_logs(log_text):
    patterns = [
        (r"ModuleNotFoundError|No module named", "Missing dependency", "Check requirements.txt or the package installation step; reproduce in a clean environment.", "Medium"),
        (r"SyntaxError|IndentationError", "Python syntax error", "Inspect the referenced file and line; run a linter or compile check before retrying.", "Medium"),
        (r"Permission denied|EACCES", "Permission issue", "Review file permissions and CI job user; avoid broad privileged permissions.", "Medium"),
        (r"Connection refused|ETIMEDOUT|Connection timed out", "Service/network unavailable", "Check service readiness, host/port, network policy, and retry behavior.", "Medium"),
        (r"AssertionError|FAILED|test failed", "Test failure", "Inspect the failing assertion and recent change; add a regression test before changing behavior.", "High"),
        (r"OutOfMemory|MemoryError|Killed", "Resource exhaustion", "Review memory limits, data volume, and whether the job can be made more efficient.", "High"),
        (r"401 Unauthorized|403 Forbidden|invalid token", "Authentication/permission failure", "Verify CI variables and token scopes. Never print tokens in logs.", "High"),
        (r"npm ERR!|ERESOLVE", "Node dependency resolution", "Review package-lock.json and version constraints; reproduce with a clean install.", "Medium"),
    ]
    found = []
    for pattern, title, recommendation, severity in patterns:
        if re.search(pattern, log_text, re.IGNORECASE):
            found.append({"title": title, "recommendation": recommendation, "severity": severity})
    if not found:
        found.append({"title": "No known signature matched", "recommendation": "Review the final error lines, exit code, job environment, and recent changes. Treat this as an initial triage, not a definitive diagnosis.", "severity": "Needs review"})
    return found

def scan_source(source):
    rules = [
        (r"eval\s*\(", "Dynamic eval()", "Avoid evaluating untrusted strings; use explicit parsing or allow-listed operations.", "High"),
        (r"pickle\.loads?\s*\(", "Python pickle deserialization", "Never load pickle data from untrusted sources; use safer data formats.", "High"),
        (r"verify\s*=\s*False", "TLS verification disabled", "Enable certificate verification for HTTPS requests.", "High"),
        (r"(password|api_key|secret|token)\s*=\s*['\"][^'\"]{5,}['\"]", "Possible hard-coded secret", "Move credentials to protected CI variables or a secret manager; rotate exposed credentials.", "Critical"),
        (r"subprocess\.(run|Popen|call)\([^)]*shell\s*=\s*True", "Shell execution enabled", "Avoid shell=True with untrusted input; pass argument lists and validate inputs.", "High"),
        (r"debug\s*=\s*True", "Debug mode enabled", "Disable debug mode in production and avoid exposing diagnostic details.", "Low"),
        (r"SELECT\s+.+\s+FROM\s+.+\+|execute\([^)]*\+", "Possible SQL query concatenation", "Use parameterized queries instead of concatenating user-controlled input.", "High"),
    ]
    findings = []
    for pattern, title, recommendation, severity in rules:
        for m in re.finditer(pattern, source, re.IGNORECASE):
            line = source.count("\n", 0, m.start()) + 1
            findings.append({"title": title, "line": line, "recommendation": recommendation, "severity": severity})
    return findings

def ask_llm(prompt):
    if not OPENAI_API_KEY:
        return None
    try:
        response = requests.post(
            f"{OPENAI_BASE_URL.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
            json={"model": OPENAI_MODEL, "messages":[
                {"role":"system","content":"You are PipelineSage AI, a cautious DevSecOps assistant. Separate evidence from assumptions. Never claim tests or scans ran unless the user supplied results. Never request or expose secrets."},
                {"role":"user","content":prompt}
            ], "temperature":0.2},
            timeout=45
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"LLM request failed: {e}. Use the rule-based findings below and check your API configuration."

def gitlab_api(path, method="GET", payload=None):
    if not GITLAB_TOKEN:
        raise RuntimeError("Set GITLAB_TOKEN in Streamlit secrets or environment variables.")
    url = f"{GITLAB_URL.rstrip('/')}/api/v4/{path.lstrip('/')}"
    resp = requests.request(method, url, headers={"PRIVATE-TOKEN": GITLAB_TOKEN},
                            json=payload, timeout=30)
    resp.raise_for_status()
    return resp.json() if resp.content else {}

def create_issue(title, description):
    if not GITLAB_PROJECT_ID:
        raise RuntimeError("Set GITLAB_PROJECT_ID in Streamlit secrets or environment variables.")
    return gitlab_api(f"projects/{GITLAB_PROJECT_ID}/issues", "POST",
                      {"title": title, "description": description})

st.markdown("""
<div class="hero">
  <div class="eyebrow">GITLAB TRANSCEND HACKATHON • DEVSECOPS AUTOMATION</div>
  <h1>🛡️ PipelineSage AI</h1>
  <p><b>Your Intelligent DevSecOps Engineer</b></p>
  <p>Detect. Diagnose. Fix. Verify.</p>
  <span class="pill">Streamlit</span><span class="pill">Python</span><span class="pill">GitLab CI/CD</span><span class="pill">AI-assisted workflows</span>
</div>
""", unsafe_allow_html=True)
st.write("")
st.info("Supervised workflow: findings and fixes are recommendations until validated. Review all changes before merging or deploying.", icon="🧭")

tab_overview, tab_logs, tab_security, tab_release, tab_gitlab, tab_settings = st.tabs([
    "Overview", "Pipeline Analyzer", "Security Review", "Release Readiness", "GitLab", "Setup"
])

if "log_findings" not in st.session_state: st.session_state.log_findings = []
if "security_findings" not in st.session_state: st.session_state.security_findings = []
if "ai_diagnosis" not in st.session_state: st.session_state.ai_diagnosis = ""

with tab_overview:
    a,b,c,d = st.columns(4)
    with a: metric("Pipeline findings", len(st.session_state.log_findings), "from current analysis")
    with b: metric("Security findings", len(st.session_state.security_findings), "from uploaded/pasted source")
    with c: metric("AI assistant", "Enabled" if OPENAI_API_KEY else "Rule-based", "LLM optional")
    with d: metric("GitLab connection", "Configured" if GITLAB_TOKEN and GITLAB_PROJECT_ID else "Not configured", "API token + project ID")
    st.subheader("Workflow")
    stages = [
        ("01", "DETECT", "Collect pipeline logs and scan reports", "#22d3ee"),
        ("02", "DIAGNOSE", "Identify probable causes and prioritize findings", "#a78bfa"),
        ("03", "FIX", "Generate remediation guidance for review", "#fb923c"),
        ("04", "VERIFY", "Run tests and security checks in CI", "#34d399"),
    ]
    cols = st.columns(4)
    for col, (num, name, desc, color) in zip(cols, stages):
        with col:
            st.markdown(f"""<div class="metric"><div class="metric-label">{num}</div>
            <div style="color:{color};font-weight:800;font-size:1.1rem">{name}</div>
            <div class="metric-label">{desc}</div></div>""", unsafe_allow_html=True)
    st.subheader("Lifecycle coverage checklist")
    st.caption("Mark stages only after they are implemented and demonstrable in your submission.")
    c1,c2,c3 = st.columns(3)
    with c1:
        st.checkbox("Plan — issue/task planning", key="stage_plan")
        st.checkbox("Create — code/fix suggestions", value=True, key="stage_create")
        st.checkbox("Verify — tests and pipeline checks", value=True, key="stage_verify")
    with c2:
        st.checkbox("Package — build artifacts/images", key="stage_package")
        st.checkbox("Secure — source/dependency review", value=True, key="stage_secure")
        st.checkbox("Release — release/promotion workflow", key="stage_release")
    with c3:
        st.checkbox("Configure — deployment configuration", key="stage_configure")
        st.checkbox("Monitor — runtime health monitoring", key="stage_monitor")
        st.checkbox("Govern — policy/audit trail", key="stage_govern")
    st.caption("The current app provides log triage, lightweight source-pattern checks, and release evaluation. Connect actual GitLab Duo Agent Platform agents/flows/MCP and demonstrate CI runs before claiming platform integration.")

with tab_logs:
    st.subheader("Pipeline Failure Analyzer")
    st.write("Paste a failed job log or upload a text log. The local rules provide first-pass triage; an optional LLM can produce a more detailed explanation.")
    upload = st.file_uploader("Upload pipeline log", type=["txt","log"], key="log_upload")
    default_log = "Installing dependencies...\nModuleNotFoundError: No module named 'requests'\nERROR: Job failed: exit code 1"
    log_text = st.text_area("Pipeline log", value=default_log, height=220, key="log_text")
    if upload is not None:
        try: log_text = upload.getvalue().decode("utf-8", errors="replace")
        except Exception: pass
    if st.button("Analyze pipeline", type="primary", key="analyze_logs"):
        st.session_state.log_findings = analyze_logs(log_text)
        if OPENAI_API_KEY:
            st.session_state.ai_diagnosis = ask_llm("Analyze this CI/CD log. Return: probable root cause, evidence lines, safe remediation steps, and verification commands. Do not claim execution.\n\nLOG:\n" + log_text[:12000])
        else:
            st.session_state.ai_diagnosis = ""
    if st.session_state.log_findings:
        st.markdown("#### Findings")
        for f in st.session_state.log_findings:
            st.warning(f"**{f['severity']} · {f['title']}**\n\n{f['recommendation']}")
        if st.session_state.ai_diagnosis:
            st.markdown("#### AI diagnosis")
            st.write(st.session_state.ai_diagnosis)
        st.download_button("Download triage report", json.dumps({
            "generated_at": datetime.utcnow().isoformat()+"Z",
            "findings": st.session_state.log_findings,
            "ai_diagnosis": st.session_state.ai_diagnosis
        }, indent=2), file_name="pipelinesage-triage-report.json", mime="application/json")

with tab_security:
    st.subheader("Security Review")
    st.write("Paste source code for lightweight pattern checks. This is a demo aid, not a replacement for SAST, dependency scanning, secret detection, or a professional security review.")
    source_upload = st.file_uploader("Upload source file", type=["py","js","ts","txt","php"], key="source_upload")
    source = st.text_area("Source code", height=250, placeholder="Paste code to review here…", key="source_text")
    if source_upload is not None:
        source = source_upload.getvalue().decode("utf-8", errors="replace")
    if st.button("Scan source patterns", type="primary"):
        st.session_state.security_findings = scan_source(source)
    if st.session_state.security_findings:
        for f in st.session_state.security_findings:
            st.error(f"**{f['severity']} · {f['title']}** — line {f['line']}\n\n{f['recommendation']}")
    elif source.strip():
        st.success("No configured pattern matched. This does not prove the code is secure.")
    if source.strip() and OPENAI_API_KEY and st.button("Ask AI for a security review"):
        st.write(ask_llm("Review this code for security concerns. Give evidence, severity, and safe remediation suggestions. Do not claim a full scan.\n\n"+source[:12000]))

with tab_release:
    st.subheader("Release Readiness")
    st.write("Combine results from the current session. For a real release gate, use GitLab CI job results and enforce policy in the pipeline.")
    tests_passed = st.selectbox("Test status", ["Not run", "Passed", "Failed"])
    pipeline_passed = st.selectbox("Pipeline status", ["Not run", "Passed", "Failed"])
    security_review = st.selectbox("Security review", ["Not run", "No known blockers", "Blockers found"])
    approval = st.checkbox("Human reviewer approved this release")
    blockers = []
    if tests_passed != "Passed": blockers.append("Tests have not passed.")
    if pipeline_passed != "Passed": blockers.append("Pipeline has not passed.")
    if security_review != "No known blockers": blockers.append("Security review is incomplete or has blockers.")
    if not approval: blockers.append("Human approval is missing.")
    if st.button("Evaluate readiness", type="primary"):
        if not blockers:
            st.success("READY FOR RELEASE REVIEW — all selected checks passed and human approval is recorded.")
        else:
            st.error("NOT READY — resolve the following before release:")
            for item in blockers: st.write(f"- {item}")
    st.caption("This dashboard records your selections; it does not independently verify test execution or deploy software.")

with tab_gitlab:
    st.subheader("GitLab Integration")
    st.write("Use GitLab API to read project metadata and create issues for findings. Configure a project access token with the minimum required scope.")
    if st.button("Test GitLab connection"):
        try:
            project = gitlab_api(f"projects/{GITLAB_PROJECT_ID}")
            st.success(f"Connected to: {project.get('path_with_namespace', 'GitLab project')}")
            st.json({k: project.get(k) for k in ["id","name","path_with_namespace","web_url","visibility"]})
        except Exception as e:
            st.error(str(e))
    issue_title = st.text_input("Issue title", "PipelineSage AI: Review pipeline findings")
    issue_desc = st.text_area("Issue description", "## Findings\n\nReview the attached PipelineSage AI triage report.\n\n## Required follow-up\n- [ ] Confirm root cause\n- [ ] Implement and review fix\n- [ ] Run tests and security scans")
    if st.button("Create GitLab issue"):
        try:
            issue = create_issue(issue_title, issue_desc)
            st.success(f"Created issue #{issue.get('iid')}: {issue.get('web_url')}")
        except Exception as e:
            st.error(str(e))
    st.warning("GitLab Duo Agent Platform integration must be configured in GitLab separately. This app does not pretend that an external LLM call is itself a Duo agent or flow.")

with tab_settings:
    st.subheader("Configuration")
    st.markdown("""
Set environment variables or create `.streamlit/secrets.toml` locally:

```toml
GITLAB_URL = "https://gitlab.com"
GITLAB_TOKEN = "your-project-access-token"
GITLAB_PROJECT_ID = "your-project-id"
OPENAI_API_KEY = "optional-llm-api-key"
OPENAI_BASE_URL = "https://api.openai.com/v1"
OPENAI_MODEL = "gpt-4o-mini"
```

Never commit `secrets.toml`, API tokens, or real credentials. Use GitLab CI/CD protected variables for pipeline jobs.
""")
    st.markdown("#### Demo mode")
    st.write("The default sample log lets you demonstrate first-pass analysis without credentials. Connect GitLab and an LLM only when you are ready.")
    st.markdown("#### Security boundaries")
    st.write("- No automatic merge or production deployment.")
    st.write("- Source-pattern checks can produce false positives and false negatives.")
    st.write("- Verify generated fixes and tests in an isolated environment.")
    st.write("- Do not upload confidential code or secrets to external services.")

st.divider()
st.caption("PipelineSage AI • Detect. Diagnose. Fix. Verify. • Supervised DevSecOps assistant")
