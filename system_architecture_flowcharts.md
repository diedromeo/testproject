# System Architecture & Flowcharts
This document contains the detailed system architecture, component integrations, and data flows using Mermaid.js diagrams for the AI-Powered Compliance & Threat Intelligence Platform.

## 1. High-Level System Architecture
This depicts the overall macro-architecture including the front-end components, Django core, Threat Intel modules, Background Task Processors (Celery/Redis), and the local AI integration with Ollama.

```mermaid
graph TD
    User((User/Admin)) -->|HTTP/HTTPS| WebUI[Django Web Interface]
    
    subgraph Frontend
        WebUI
        Map[Leaflet 2D Map]
        Globe[Globe.gl 3D Viz]
        Charts[Chart.js / Dashboards]
    end
    
    subgraph Backend Core [Django Backend Core]
        CoreAuth[Core System & Auth]
        Compliance[Compliance Module]
        Vendors[Vendor Management]
        Alerts[Alerts Engine]
        Advisories[Advisory Engine]
    end
    
    subgraph Threat Intelligence
        CVE[CVE Engine]
        ThreatIntel[Live Threat Intel]
        DarkWeb[Darkweb / OSINT]
    end
    
    subgraph AI Processing
        AIAssistant[AI Assistant]
    end

    subgraph Infrastructure
        DB[(SQLite / PostgreSQL Database)]
        Redis[(Redis Cache / Broker)]
        Celery[Celery Task Workers]
        Ollama((Local Ollama LLM))
    end
    
    WebUI <--> Backend Core
    WebUI <--> Threat Intelligence
    WebUI <--> AI Processing
    
    Backend Core <--> DB
    Threat Intelligence <--> DB
    
    Threat Intelligence <--> Redis
    Redis <--> Celery
    Celery -->|Fetch Data Async| ExternalAPIs[NVD API, Google OSINT, etc.]
    
    AIAssistant <--> Ollama
    
    Map & Globe <--> ThreatIntel
```

## 2. Threat Intelligence & OSINT Execution Flow
This sequence details how an Admin triggers an OSINT scan (like Google Enumeration or Darkweb sweep) taking advantage of the async Celery/Redis architecture to prevent server blocking.

```mermaid
sequenceDiagram
    participant Admin
    participant DjangoApp
    participant Redis_Broker
    participant Celery_Worker
    participant OSINT_Tools
    participant Database

    Admin->>DjangoApp: Start OSINT Scan (e.g., Google Enum)
    activate DjangoApp
    DjangoApp->>Redis_Broker: Publish Task (osint_scan_task)
    DjangoApp-->>Admin: Task Queued / Pending Status
    deactivate DjangoApp
    
    activate Celery_Worker
    Redis_Broker->>Celery_Worker: Deliver Task
    Celery_Worker->>OSINT_Tools: Execute specific OSINT script/module
    activate OSINT_Tools
    OSINT_Tools-->>Celery_Worker: Return results (JSON/Dict)
    deactivate OSINT_Tools
    
    Celery_Worker->>Database: Save OSINT results / Generate Alerts
    deactivate Celery_Worker
    
    Admin->>DjangoApp: View Results
    DjangoApp->>Database: Query completed scan data
    Database-->>DjangoApp: Scan data records
    DjangoApp-->>Admin: Render insights (Graphs/Tables)
```

## 3. CVE Ingestion & Vulnerability Alerting Flow
Details the background process that fetches new Common Vulnerabilities and Exposures (CVEs) and maps them to currently logged vendor risk profiles.

```mermaid
flowchart TD
    Timer((Scheduled Task)) -->|Triggers| Fetcher[CVE Fetcher Job]
    Fetcher -->|API Request| NVD{NVD API / FedVTE / MITRE}
    NVD -->|JSON Response| Parser[CVE Parser]
    Parser --> Matcher[Vendor Asset Matcher]
    
    Matcher -->|Check against DB| Assets[(Vendor Assets DB)]
    
    Matcher -->|If tech stack match found| AlertGen[Alert Generator]
    Matcher -->|If critical impact| AdvGen[Advisory Generator]
    
    AlertGen --> DBUpdate[(Update Alerts DB)]
    AdvGen --> DBUpdate
    
    DBUpdate --> Notify[Email/UI Notification]
    Notify --> Admin((System Admin / Vendor Owner))
```

## 4. AI Assistant (Ollama) Analysis Flow
Highlights how the AI Assistant leverages locally hosted LLMs through Ollama to analyze CVEs, provide remediation scripts, or chat contextually about threat landscapes.

```mermaid
sequenceDiagram
    participant User
    participant ChatUI
    participant AI_Assistant_View
    participant DB as Database
    participant Ollama_LLM

    User->>ChatUI: Ask Question (e.g. "Analyze CVE-2024-XXXX impact")
    ChatUI->>AI_Assistant_View: Send Prompt (POST)
    activate AI_Assistant_View
    
    AI_Assistant_View->>DB: Fetch System Context (CVE details, Vendor assets)
    DB-->>AI_Assistant_View: Contextual Data
    
    AI_Assistant_View->>Ollama_LLM: Formulate Master Prompt (User Query + Context)
    activate Ollama_LLM
    Ollama_LLM-->>AI_Assistant_View: Generate Insights / Remediation / Analysis
    deactivate Ollama_LLM
    
    AI_Assistant_View-->>DB: Store Chat History (Optional)
    AI_Assistant_View-->>ChatUI: Stream/Return AI Response
    deactivate AI_Assistant_View
    ChatUI-->>User: Display Formatted AI Advice
```

## 5. Vendor Compliance & Risk Scoring Engine
How different signals (OSINT leaks, CVEs, Audit records) are combined to produce a unified vendor risk score and highlight compliance gaps.

```mermaid
graph LR
    subgraph Signal Inputs
        VendorData[Vendor Tech Stack & Details]
        CVEData[Active CVEs affecting Tech]
        OSINTRisk[OSINT Leaks - Passwords, Darkweb]
        AuditData[Compliance Audit History/Forms]
    end
    
    subgraph Risk & Rule Engines
        ScoreCalc[Risk Score Calculator]
        RuleEngine[Compliance Rule Matcher]
    end
    
    subgraph Actionable Outputs
        RiskScore((Overall Vendor Risk Score))
        ComplianceGap((Compliance Gaps e.g. DPDP, GDPR))
        MandateAlert((Mandate Breach Alerts))
    end
    
    VendorData --> ScoreCalc
    CVEData --> ScoreCalc
    OSINTRisk --> ScoreCalc
    
    AuditData --> RuleEngine
    VendorData --> RuleEngine
    
    ScoreCalc --> RiskScore
    RuleEngine --> ComplianceGap
    
    ComplianceGap --> MandateAlert
    RiskScore --> MandateAlert
```
