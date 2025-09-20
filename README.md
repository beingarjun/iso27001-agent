# ISO 27001 Agent - Enterprise GRC Platform# ISO 27001 Agent 🛡️# ISO 27001 Agent 🛡️



A comprehensive ISO 27001 compliance automation platform inspired by leading GRC solutions like Vanta, Drata, and Secureframe.



## 🎯 MissionAn intelligent AI-powered agent for ISO 27001 compliance assessment, audit management, and security documentation.An intelligent AI-powered agent for ISO 27001 compliance assessment, audit management, and security documentation. Built with FastAPI, LangGraph, and Next.js.

Automate ISO 27001 compliance for startups and enterprises with human-in-the-loop workflows, continuous monitoring, and audit-ready evidence collection.



## 🏗️ Architecture

## 🚀 Quick Start## ✨ Features

### Backend (FastAPI + LangGraph + LCEL)

- **Multi-tenant**: Organization-based data isolation

- **Compliance Engine**: LangGraph workflows with approval gates

- **Evidence Collection**: Immutable storage with cryptographic hashing### Prerequisites- **AI-Powered Compliance Assessment**: Automated analysis of your organization's security posture

- **Risk Management**: Automated risk assessment with time-boxed acceptance

- **Audit Trails**: Complete activity logging for compliance- Python 3.11+- **Multi-Tenant Architecture**: Company and project-based organization



### Frontend (Next.js + TypeScript)- Node.js 18+- **Google OAuth Integration**: Seamless authentication and user management

- **Compliance Dashboard**: Real-time compliance posture

- **Approval Workflows**: Human-in-the-loop decision making- Docker (optional)- **Real-time Processing**: Server-sent events for live audit progress

- **Evidence Management**: Document and screenshot collection

- **Risk Register**: Visual risk tracking and CAPA management- **Comprehensive Reporting**: Detailed compliance reports and findings

- **Audit Preparation**: Export-ready compliance packages

### Development Setup- **Modular Agent System**: LangGraph workflows for complex compliance tasks

## 🔒 Security Features

- **Modern UI**: Clean, responsive interface built with Next.js and Tailwind CSS

### Continuous Monitoring

- **Code Security**: Bandit, Safety, npm audit**Backend:**

- **Infrastructure**: Cloud configuration scanning

- **SSL/TLS**: Certificate monitoring and validation```bash## 🏗️ Architecture

- **Access Control**: MFA enforcement tracking

- **Data Privacy**: GDPR/DPDP compliance mappingcd backend



### Evidence Integritypython -m venv venv```

- **Immutable Storage**: SHA-256 hashing for all evidence

- **Audit Trails**: Complete access and modification logssource venv/bin/activate  # Windows: venv\Scripts\activate├── backend/           # FastAPI backend with AI agents

- **Version Control**: Document lifecycle management

- **Retention Policies**: Automated evidence lifecyclepip install -r requirements.txt│   ├── agents/        # LangGraph workflows and LCEL pipelines



## 🏢 Enterprise Featuresuvicorn main:app --reload│   ├── reporting/     # Report generation and templates



### Multi-Framework Support```│   └── auth.py        # Authentication and authorization

- ISO 27001:2022

- SOC 2 Type II├── frontend/          # Next.js frontend application

- GDPR/DPDP India

- PCI DSS**Frontend:**│   ├── src/components # Reusable UI components

- HIPAA

```bash│   ├── src/pages/     # Application pages and routing

### Business Continuity

- **BC/DR Drills**: Automated testing with RTO/RPO metricscd frontend│   └── src/lib/       # Utilities and API client

- **Incident Response**: Workflow automation

- **Recovery Planning**: Evidence-based recovery proceduresnpm install└── .github/           # CI/CD workflows and automation



### Governancenpm run dev```

- **Management Reviews**: Quarterly business reviews with KPIs

- **Internal Audits**: Structured audit planning and execution```

- **Policy Management**: Version-controlled document library

- **Training Tracking**: Compliance awareness programs## 🚀 Quick Start



## 🚀 Quick Start### Access



### Backend Setup- Frontend: http://localhost:3000### Prerequisites

```bash

cd backend- Backend API: http://localhost:8000

pip install -r requirements.txt

export OPENAI_API_KEY=your_key_here- API Docs: http://localhost:8000/docs- **Python 3.11+**

uvicorn app:app --reload

```- **Node.js 18+**



### Frontend Setup## 🏗️ Architecture- **Docker & Docker Compose** (optional)

```bash

cd frontend- **OpenAI API Key**

npm install

npm run dev```- **Google OAuth Credentials** (optional)

```

iso27001-agent/

## 📊 Compliance Dashboard

├── backend/          # FastAPI + AI agents### 1. Clone the Repository

### Real-time Metrics

- **Control Coverage**: % of ISO 27001 controls implemented├── frontend/         # Next.js + TypeScript

- **Risk Posture**: Open/mitigated/accepted risks

- **CAPA Status**: Corrective actions tracking├── docker/           # Docker configurations```bash

- **Evidence Health**: Collection and validation status

└── .github/          # CI/CD workflowsgit clone https://github.com/beingarjun/iso27001-agent.git

### Audit Readiness

- **SoA Export**: Statement of Applicability with rationales```cd iso27001-agent

- **Risk Register**: Complete risk assessment documentation

- **Evidence Package**: Immutable compliance artifacts```

- **Management Reviews**: Quarterly governance records

## ✨ Features

## 🔐 Access Control

### 2. Environment Setup

### Role-Based Access

- **Admin**: Full system access and configuration- 🤖 AI-powered compliance assessment

- **Compliance Manager**: Risk and control management

- **Auditor**: Read-only evidence and report access- 🏢 Multi-tenant company managementCopy the environment files and configure your settings:

- **Viewer**: Dashboard and basic reporting

- 🔐 JWT + Google OAuth authentication

### SSO Integration

- Google Workspace- 📊 Real-time audit progress```bash

- Azure AD

- Okta- 📋 Comprehensive reporting# Backend environment

- SAML 2.0

- 🎯 Modern, responsive UIcp backend/.env.example backend/.env

## 📈 Pricing Tiers



### Starter ($99/month)

- Up to 50 employees## 📄 License# Frontend environment  

- Basic ISO 27001 controls

- Monthly reportscp frontend/.env.example frontend/.env.local

- Email support

MIT License - see LICENSE file for details.```

### Professional ($299/month)

- Up to 200 employees**Backend Configuration** (`backend/.env`):

- Multi-framework support```env

- Continuous monitoring# Database

- Priority supportDATABASE_URL=sqlite:///./app.db



### Enterprise ($999/month)# Security

- Unlimited employeesSECRET_KEY=your-super-secret-key-here

- Custom integrationsALGORITHM=HS256

- Dedicated success managerACCESS_TOKEN_EXPIRE_MINUTES=30

- Advanced analytics

# AI Configuration

## 🛡️ Acceptance Criteria (Audit-Ready)OPENAI_API_KEY=sk-your-openai-api-key

MODEL_NAME=gpt-4

✅ **Evidence**: Every finding has raw logs, hashes, approver, timestamp, and control linkage  

✅ **SoA**: Export lists included/excluded controls with rationale and owners  # Google OAuth (Optional)

✅ **Risk**: Each HIGH finding has CAPA or accepted risk with expiry and reviewer  GOOGLE_CLIENT_ID=your-google-client-id

✅ **BC/DR**: Successful restore drill in last 90 days with RTO/RPO metrics  GOOGLE_CLIENT_SECRET=your-google-client-secret

✅ **Access**: All admin accounts MFA-enforced; exceptions time-boxed with approvals  

✅ **Privacy**: Data inventory exists; retention + cookie banner verified; DPDP/GDPR mapping documented  # CORS

CORS_ORIGINS=["http://localhost:3000"]

## 📞 Support```



- **Documentation**: [docs.iso27001-agent.com](https://docs.iso27001-agent.com)**Frontend Configuration** (`frontend/.env.local`):

- **Community**: [discord.gg/iso27001](https://discord.gg/iso27001)```env

- **Enterprise**: enterprise@iso27001-agent.comNEXT_PUBLIC_API_BASE=http://localhost:8000

NEXT_PUBLIC_GOOGLE_CLIENT_ID=your-google-client-id

---```



*Built with ❤️ for compliance teams worldwide*### 3. Development Setup

#### Option A: Local Development

**Backend Setup:**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # For development

# Run the backend
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

**Frontend Setup:**
```bash
cd frontend
npm install

# Run the frontend
npm run dev
```

#### Option B: Docker Development

```bash
# Start all services
docker-compose -f docker-compose.dev.yml up --build

# Or start individual services
docker-compose -f docker-compose.dev.yml up backend
docker-compose -f docker-compose.dev.yml up frontend
```

### 4. Access the Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

## 🔐 Authentication

The application supports both email/password and Google OAuth authentication:

1. **Company Registration**: Create a new company account
2. **User Signup**: Join an existing company or create a new one
3. **Project Management**: Organize compliance work by projects
4. **Role-Based Access**: Admin and member roles with appropriate permissions

## 🤖 AI Agents

### LangGraph Workflows

The system uses LangGraph for complex multi-step compliance assessments:

- **Document Analysis**: Parse and analyze security documents
- **Gap Assessment**: Identify compliance gaps and recommendations
- **Risk Evaluation**: Assess and prioritize security risks
- **Report Generation**: Create comprehensive audit reports

### LCEL Pipelines

Langchain Expression Language pipelines for specific tasks:

- **Text Normalization**: Clean and structure input documents
- **Content Extraction**: Extract relevant compliance information
- **Finding Classification**: Categorize and score findings

## 📊 Usage

### 1. Create a Company

Sign up and create your organization:

```bash
curl -X POST "http://localhost:8000/auth/signup" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@company.com",
    "password": "secure_password",
    "full_name": "Admin User",
    "company_name": "Your Company"
  }'
```

### 2. Start a Compliance Assessment

Navigate to the dashboard and:

1. Create a new project
2. Upload relevant documents
3. Start the AI-powered assessment
4. Monitor progress in real-time
5. Review findings and recommendations

### 3. Generate Reports

Export comprehensive compliance reports in multiple formats.

## 🛠️ Development

### Code Quality

The project includes comprehensive code quality tools:

```bash
# Backend
cd backend
black .                 # Code formatting
flake8 .                # Linting
mypy .                  # Type checking
bandit -r .             # Security scanning
pytest tests/           # Run tests

# Frontend
cd frontend
npm run lint            # ESLint
npm run type-check      # TypeScript validation
npm run build           # Build check
```

### Pre-commit Hooks

Install pre-commit hooks for automatic code quality checks:

```bash
pip install pre-commit
pre-commit install
```

### Testing

**Backend Tests:**
```bash
cd backend
pytest tests/ --cov=. --cov-report=html
```

**Frontend Tests:**
```bash
cd frontend
npm test
```

## 🚢 Deployment

### Docker Production

```bash
# Build and start production services
docker-compose up --build -d

# Scale services
docker-compose up --scale backend=3 --scale frontend=2
```

### Environment Variables

For production deployment, ensure all environment variables are properly configured:

- Use PostgreSQL instead of SQLite
- Set strong secret keys
- Configure proper CORS origins
- Set up Redis for session management
- Configure Google OAuth for production domain

### CI/CD

The project includes GitHub Actions workflows for:

- **Continuous Integration**: Automated testing and quality checks
- **Security Scanning**: Vulnerability assessments
- **Dependency Updates**: Automated dependency management
- **Docker Builds**: Automated image building and publishing

## 📝 API Documentation

### Authentication Endpoints

- `POST /auth/signup` - User registration
- `POST /auth/login` - User login
- `POST /auth/google` - Google OAuth login
- `GET /auth/me` - Get current user

### Compliance Endpoints

- `POST /assessment/start` - Start new assessment
- `GET /assessment/{id}` - Get assessment status
- `GET /assessment/{id}/stream` - Real-time progress stream
- `GET /reports/{id}` - Download compliance report

Full API documentation is available at `/docs` when running the backend.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes and add tests
4. Ensure code quality checks pass
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:

- **Issues**: [GitHub Issues](https://github.com/beingarjun/iso27001-agent/issues)
- **Discussions**: [GitHub Discussions](https://github.com/beingarjun/iso27001-agent/discussions)
- **Documentation**: Check the `/docs` endpoint for API documentation

## 🗺️ Roadmap

- [ ] Advanced reporting templates
- [ ] Integration with popular security tools
- [ ] Multi-language support
- [ ] Mobile application
- [ ] Enterprise SSO integration
- [ ] Advanced analytics dashboard
- [ ] Compliance workflow automation
- [ ] Third-party audit integrations

---

**Built with ❤️ for better cybersecurity compliance**
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
