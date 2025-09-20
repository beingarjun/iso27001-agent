# ISO 27001 Agent

An AI-powered ISO 27001 compliance agent with human-in-the-loop approval workflow, built with FastAPI, LangGraph, and Next.js.

## 🏗️ Architecture

```
iso27001-agent/
├── backend/                 # FastAPI + LangGraph + LCEL
│   ├── app.py              # Main FastAPI application
│   ├── deps.py             # Database & settings
│   ├── models.py           # SQLModel entities
│   ├── agents/
│   │   ├── graph.py        # LangGraph workflow
│   │   ├── lcel_pipeline.py # LCEL chains
│   │   └── tools/          # Security scanners
│   │       ├── scanners.py
│   │       └── normalize.py
│   ├── reporting/
│   │   └── reporter.py     # Report generation
│   └── controls_map.yaml   # ISO 27001 controls mapping
├── frontend/               # Next.js + TypeScript + Tailwind
│   ├── src/
│   │   ├── pages/
│   │   │   ├── index.tsx   # Dashboard
│   │   │   ├── findings/   # Findings detail & approval
│   │   │   └── stream.tsx  # Live scan stream
│   │   ├── components/
│   │   └── lib/api.ts      # API client
│   └── package.json
└── docker-compose.yml      # Development environment
```

## 🚀 Features

- **Automated Security Scanning**: npm audit, safety, bandit, SSL checks
- **AI-Powered Analysis**: LangGraph workflow with GPT for intelligent findings
- **Human-in-the-Loop**: Security officer approval workflow for critical findings
- **Real-time Streaming**: Server-Sent Events for live scan progress
- **ISO 27001 Mapping**: Automatic mapping to ISO 27001 controls
- **Evidence Generation**: Markdown and PDF compliance reports

## 🛠️ Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- OpenAI API key

### Backend Setup

```bash
cd backend
pip install -r requirements.txt
export OPENAI_API_KEY=your_openai_key
uvicorn app:app --reload --port 8000
```

### Frontend Setup

```bash
cd frontend
npm install
echo "NEXT_PUBLIC_API_BASE=http://localhost:8000" > .env.local
npm run dev
```

### Docker Setup

```bash
docker-compose up --build
```

## 🔄 Workflow

1. **Start Scan**: Analyst initiates security scan for target host
2. **AI Analysis**: LangGraph agent runs parallel security checks
3. **Risk Assessment**: AI categorizes findings by severity and maps to ISO controls
4. **Human Gate**: High-severity findings require security officer approval
5. **Report Generation**: Automated compliance evidence generation

## 🏃‍♂️ Usage

### Start a Scan

```bash
curl -X POST "http://localhost:8000/scan/start" \
  -H "Content-Type: application/json" \
  -d '{"host": "yourwebsite.com"}'
```

### Approve/Reject Findings

```bash
# Approve finding
curl -X POST "http://localhost:8000/approve" \
  -H "Content-Type: application/json" \
  -d '{"finding_id": 1, "approved_by": "security@company.com", "reason": "Risk accepted"}'

# Reject finding  
curl -X POST "http://localhost:8000/reject" \
  -H "Content-Type: application/json" \
  -d '{"finding_id": 1, "approved_by": "security@company.com", "reason": "False positive"}'
```

### Continue After Approvals

```bash
curl -X POST "http://localhost:8000/scan/continue" \
  -H "Content-Type: application/json" \
  -d '{"run_id": 1, "host": "yourwebsite.com"}'
```

## 🔒 Security

- RBAC with viewer/approver/admin roles
- Audit logging of all approval decisions
- Secure API endpoints with authentication
- Environment-based configuration

## 📊 Dashboard

Access the web dashboard at `http://localhost:3000`:

- **Scan Dashboard**: Start scans and view status
- **Findings Table**: Review security findings with severity
- **Approval Panel**: Approve/reject high-severity findings
- **Live Stream**: Real-time scan progress and AI explanations

## 🧪 Development

### Backend Tests

```bash
cd backend
pytest tests/
```

### Frontend Tests

```bash
cd frontend
npm test
```

### Linting

```bash
# Backend
cd backend
flake8 .
black .

# Frontend
cd frontend
npm run lint
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support, please open an issue on GitHub or contact the development team.

---

**Built with ❤️ for ISO 27001 compliance automation**
