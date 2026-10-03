# SentinelX
### Production-Grade Defensive API Security & Threat Intelligence Platform

SentinelX is a full-stack cybersecurity platform engineered to monitor API ingress traffic, identify anomalous patterns, enforce sliding-window rate limiting, execute safe configuration audits, and maintain an immutable audit trail.

Unlike mock demonstration projects, SentinelX implements **real working security controls**: genuine password hashing, signed JWT token lifecycles, sliding-window rate limiters with HTTP 429 quarantine, active regex and anomaly detection pipelines, safe HTTP header scanning, and granular Role-Based Access Control (RBAC).

---

## Key Features

1. **API Ingress Telemetry & Monitoring**
   - High-throughput logging of HTTP methods, response times, status codes, source IPs, and security flags.
   - Granular multi-parameter filtering (by method, status group, endpoint, keyword).
   - Detailed payload inspection drawer displaying headers and user agent telemetry.

2. **Role-Based Access Control (RBAC)**
   - Cryptographically enforced JWT authentication (`HS256`).
   - Salting and hashing via standard bcrypt algorithms.
   - Strict hierarchical privilege tiers:
     - **Admin**: Full control over users, roles, rules, and audit configurations.
     - **Security Analyst**: Triage incidents, tune detection rules, run configuration audits, and add investigation notes.
     - **Viewer**: Read-only observability over metrics, logs, and health states.

3. **Rule-Based Defensive Threat Detection**
   - Transparent, auditable sliding-window and signature rules (no opaque black-box AI claims):
     - `RULE_AUTH_BRUTE_FORCE`: Detects $\ge 5$ failed login attempts in 60 seconds.
     - `RULE_REQ_FLOOD`: Flags volumetric velocity bursts exceeding 50 requests in 10 seconds.
     - `RULE_TOKEN_ABUSE`: Quarantines repeated forged or expired JWT Bearer attempts.
     - `RULE_INJECTION_PROBE`: Detects SQL injection boolean assertions and directory traversal patterns (`../`, `%2e%2e`).
     - `RULE_ERROR_BURST`: Alerts on sharp spikes of 5xx errors from upstream targets.
     - `RULE_UNAUTHORIZED_ENUM`: Detects automated reconnaissance targeting `/.env`, `/wp-admin`, `/actuator`.

4. **Sliding-Window Rate Limiting**
   - Real-time timestamp bucket tracking per client IP and authenticated identity.
   - Configurable limits (e.g. 60 req/min anonymous, 300 req/min authenticated).
   - Enforces automatic temporary quarantine blocks and standard `Retry-After` headers.
   - Interactive burst simulator to test rate limits live.

5. **Security Events & Incident Triage (SOC Queue)**
   - Incident lifecycle management (`OPEN`, `UNDER_INVESTIGATION`, `RESOLVED`, `FALSE_POSITIVE`).
   - Investigator note-taking with permanent operator attribution.

6. **Defensive Security Configuration Audit**
   - Non-intrusive automated inspection of HTTP security headers:
     - TLS/HTTPS transport encryption.
     - `Strict-Transport-Security` (HSTS).
     - `Content-Security-Policy` (CSP).
     - `X-Frame-Options` (Clickjacking mitigation).
     - `X-Content-Type-Options` (MIME sniffing defense).
     - Wildcard CORS policy analysis (`*` vs explicit origins).
     - Server and framework banner exposure (`Server`, `X-Powered-By`).

7. **API Health & Availability Monitoring**
   - Active, rate-limited GET/HEAD probes against authorized target APIs.
   - Real-time latency tracking and availability percentage calculations.

8. **Immutable System Audit Trail**
   - Structured logging of all administrative actions, status changes, and authentication outcomes with timestamps and client IPs.

---

## SentinelX Dashboard

The SentinelX dashboard provides a centralized view of API security telemetry, request activity, suspicious traffic, threat severity, authentication failures, and rate-limiting events.

![SentinelX Security Dashboard](Screenshot%202026-10-04%20002752.png)


## Architecture

SentinelX provides a dual-runtime deployment model:
1. **Python FastAPI Backend (`backend/`)**: Built with SQLAlchemy 2.0 async ORM, Pydantic v2 schemas, JWT authentication, and full pytest test suites.
2. **Full-Stack Node.js/Vite Engine (`server.ts` & `src/`)**: Provides immediate zero-configuration interactivity in modern containerized preview environments.

```
Client (React 19 + TypeScript + Tailwind CSS)
   │
   ▼
Ingress Security Filter (HSTS, CSP, XFO, XCTO)
   │
   ▼
Rate Limiter Middleware (Sliding Window / 429 Cooldown)
   │
   ▼
Authentication & RBAC (JWT Verification, bcrypt Hashing)
   │
   ▼
Defensive Threat Detection Pipeline (Signatures & Windows)
   │
   ▼
Database Persistence (SQLAlchemy 2.0 ORM / PostgreSQL / SQLite)
```

---

## Tech Stack

- **Backend**: Python 3.11, FastAPI, SQLAlchemy 2.0, Pydantic v2, Passlib (bcrypt), Python-JOSE (JWT), HTTPX, Pytest.
- **Frontend**: React 19, TypeScript, Tailwind CSS, Lucide Icons, Custom Responsive SVG Data Charts.
- **Database**: PostgreSQL 16 (production) / SQLite with aiosqlite (local portable execution).
- **Deployment**: Docker, Multi-stage Dockerfiles, Docker Compose, Nginx.

---

## Directory Structure

```
sentinelx/
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI application entry point
│   │   ├── core/                    # Settings & security configuration
│   │   ├── database/                # SQLAlchemy async engine & sessionmaker
│   │   ├── models/                  # SQLAlchemy 2.0 ORM database models
│   │   ├── schemas/                 # Pydantic v2 validation models
│   │   ├── security/                # RBAC & sliding-window rate limiter
│   │   ├── detection/               # Defensive threat detection engine
│   │   ├── services/                # Health checker, config audit, audit logger
│   │   └── api/v1/                  # Modular FastAPI routers
│   ├── tests/                       # Pytest test suite (auth, detection, rate limit)
│   ├── requirements.txt             # Python backend dependencies
│   └── Dockerfile                   # Backend production Docker image
├── src/                             # React TypeScript Frontend
│   ├── components/                  # Sidebar, Navbar, MetricCard, SVG Charts, Simulator
│   ├── context/                     # AuthContext (JWT, session, persona switcher)
│   ├── pages/                       # Dashboard, Monitoring, Events, Rules, Health, Audit
│   ├── services/                    # Centralized API client
│   └── types/                       # Shared TypeScript data contracts
├── docs/                            # Comprehensive technical documentation
│   ├── architecture.md
│   ├── api.md
│   ├── security.md
│   └── detection-engine.md
├── docker-compose.yml               # Multi-container orchestration
├── server.ts                        # Full-stack runtime server bridge
└── package.json
```

---

## Quickstart & Local Setup

### Option 1: Full-Stack Mode (Instant Local Preview)

```bash
# 1. Install dependencies
npm install

# 2. Run full-stack development server
npm run dev

# 3. Open browser at http://localhost:3000
```

### Option 2: Python FastAPI Backend

```bash
# 1. Navigate to backend directory
cd backend

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Start FastAPI server with live reload
uvicorn app.main:app --reload --port 8000

# 5. Access OpenAPI documentation at http://localhost:8000/docs
```

### Option 3: Docker Compose (PostgreSQL + Backend + Frontend)

```bash
# Build and start all multi-container services
docker-compose up --build -d

# Verify running containers
docker-compose ps

# Access frontend at http://localhost:3000
# Access backend API at http://localhost:8000/docs
```

---

## Running Automated Tests

```bash
# Run backend pytest suite
cd backend
pytest tests/ -v
```

Tests cover:
- User registration, password verification, and JWT issuance.
- Role-Based Access Control (Admin route access denial for Viewers).
- Threat detection engine signature matching (SQLi, path traversal, brute force).
- Sliding-window rate limiter threshold and 429 responses.
- Defensive configuration audit and HTTP security header inspections.

---

## Default Evaluator Personas

For immediate testing, three pre-configured accounts are provided:
- **Admin**: `admin` / `AdminPass123!` (Full control)
- **Security Analyst**: `analyst` / `AnalystPass123!` (SOC triage, rule tuning, audits)
- **Viewer**: `viewer` / `ViewerPass123!` (Read-only observability)

---

## Ethical Use & Authorized Testing Notice

SentinelX is developed exclusively for defensive security monitoring and authorized systems auditing. Operators must only configure health checks and security configuration scans against API endpoints they own or have obtained written authorization to inspect. The platform does NOT execute aggressive penetration testing, vulnerability exploitation, or denial-of-service payloads.
