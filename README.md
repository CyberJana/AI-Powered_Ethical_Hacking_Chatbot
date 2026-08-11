# AI-Powered Ethical Hacking Chatbot

A security-first learning and analysis platform for authorized penetration-testing labs,
CTFs, defensive security, digital forensics, and secure-code education.

## Phase 1 status

This initial foundation includes:

- Environment-driven configuration with no embedded credentials.
- SQLite and SQLAlchemy domain models for conversations, investigations, findings,
  evidence, uploads, reports, and knowledge documents.
- A FastAPI health endpoint, policy classification endpoint, and dashboard-statistics endpoint.
- A Streamlit SOC-style dashboard backed by persisted aggregate statistics.
- A request safety policy that blocks credential theft, malware, destructive actions,
  control evasion, and unauthorized access guidance.
- Provider-neutral AI chat with OpenAI-compatible endpoint support, persisted conversation
  history, export and deletion API endpoints, and a Streamlit chat experience.
- Structured ethical-hacking learning topics and an explicit-authorization lab-results
  interpreter that only analyzes already-collected text.
- Local vulnerability analysis that derives a consistent CWE, severity, impact, detection,
  remediation, risk explanation, and CVE reference from supplied evidence.
- A non-executing static code analyzer for clear SQL injection, command injection, dynamic
  execution, unsafe deserialization, hard-coded-secret, and weak-hash patterns.

## Installation

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

## Running locally

Start the API:

```bash
uvicorn backend.api:app --reload
```

Start the dashboard in a second terminal:

```bash
streamlit run app.py
```

To enable an OpenAI-compatible provider, set `LLM_PROVIDER=openai_compatible` plus
`LLM_API_BASE`, `LLM_API_KEY`, and `LLM_MODEL` in `.env`. The default `disabled` provider
keeps the application offline until you configure an AI service.

## Testing

```bash
pytest
```

## Security model

The application classifies every request before future AI or target-specific analysis
services process it. It is designed only for authorized labs, education, defensive work,
and evidence-preserving forensics. It does not execute uploaded files or user commands.