# PipelineSage AI — Your Intelligent DevSecOps Engineer

**Detect. Diagnose. Fix. Verify.**

PipelineSage AI is a Streamlit-first DevSecOps assistant for triaging CI/CD failures, reviewing source-code patterns, suggesting remediation, and summarizing release readiness.

> **Status:** Hackathon MVP/scaffold. The dashboard includes working rule-based log triage, lightweight source-pattern checks, optional OpenAI-compatible LLM assistance, and optional GitLab API operations. GitLab Duo Agent Platform agents/flows/MCP must be configured and demonstrated separately; an external LLM call alone does not satisfy that requirement.

## Features

- Pipeline log analyzer with common error signatures and downloadable JSON report
- Lightweight source-pattern security checks with remediation guidance
- Optional LLM explanation via an OpenAI-compatible Chat Completions API
- Release-readiness checklist with human approval gate
- Optional GitLab API connection test and issue creation
- Single-file Streamlit application (`app.py`)
- GitLab CI pipeline for syntax validation

## Quick start

Requires Python 3.10 or newer.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
streamlit run app.py
```

Open the local URL printed by Streamlit. The Pipeline Analyzer includes a sample log so the demo can run without API credentials.

## Configuration

Create `.streamlit/secrets.toml` locally (never commit it):

```toml
GITLAB_URL = "https://gitlab.com"
GITLAB_TOKEN = "your-project-access-token"
GITLAB_PROJECT_ID = "your-project-id"

# Optional:
OPENAI_API_KEY = "your-api-key"
OPENAI_BASE_URL = "https://api.openai.com/v1"
OPENAI_MODEL = "gpt-4o-mini"
```

Alternatively, set these as environment variables. Use a GitLab project access token with minimum necessary scopes. GitLab issue creation generally requires API permissions. Do not put secrets in source code, screenshots, logs, or public repositories.

## GitLab CI/CD

The included `.gitlab-ci.yml` performs Python syntax validation. To demonstrate real pipeline activity:

1. Push this repository to GitLab.
2. Confirm the pipeline runs successfully.
3. Add actual test, SAST, dependency scanning, and secret-detection jobs as appropriate.
4. Save screenshots or link to visible pipeline history in your hackathon submission.

## GitLab Duo Agent Platform requirement

The hackathon requires GitLab Duo Agent Platform features such as agents, flows, or MCP clients. Configure the relevant feature in your GitLab environment and document the real flow used. A recommended supervised workflow is:

1. A pipeline failure or issue triggers the workflow.
2. An agent analyzes logs and relevant repository context.
3. A security step examines scan findings.
4. A remediation agent proposes a patch or merge request.
5. CI tests and security checks verify the patch.
6. A human approves merge or production deployment.

The Streamlit app is the dashboard and supporting tool; do not claim that the above agent orchestration is complete until it is actually wired into GitLab and verified.

## Limitations and safety

- The built-in source scanner is a small set of regular-expression checks, not a full SAST product.
- Release readiness reflects selected statuses and does not independently prove that jobs ran.
- LLM responses are suggestions and may be wrong.
- Never auto-merge or deploy based only on an LLM response.
- Do not submit secrets or confidential source code to third-party models.
- Keep production actions behind least-privilege permissions and human approval.

## Suggested demo flow

1. Open **Pipeline Analyzer** and analyze the included sample failure.
2. Open **Security Review** and paste a small example containing a deliberately unsafe pattern.
3. Open **Release Readiness** and show a blocked release, then a release that passes the selected gates.
4. If configured, test GitLab connectivity and create a triage issue.
5. Show the GitLab CI pipeline history and the separately configured Duo Agent Platform workflow.

## Built with

Python · Streamlit · GitLab API · GitLab CI/CD · Optional OpenAI-compatible LLM API

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
