# Project Flowcharts

Here are all the necessary system flowcharts and architecture diagrams for the Threat Intelligence and Compliance Platform.

## 1. Complete System Architecture
```mermaid
graph TD
    User((Admin User)) -->|Interacts with| UI[Django Frontend / Maps / Globe]
    
    subgraph Django Core
        Auth[Authentication]
        Compliance[Compliance Module]
        Vendors[Vendor Management]
        Alerts[Alerts Engine]
    end
    
    subgraph Threat Engines
        CVE[CVE Ingestion]
        Intel[Live Threat Intel]
        OSINT[Darkweb / OSINT Exec]
    end
    
    subgraph Background Processing
        DB[(Database)]
        Redis[(Redis Queue)]
        Celery[Celery Async Workers]
        Ollama((Local Ollama LLM))
    end
    
    UI <--> Core
    UI <--> Threat
    
    Core <--> DB
    Threat <--> DB
    
    Threat <--> Redis
    Redis <--> Celery
    Celery <-->|External APIs| APIs[NVD API, Scripts]
    
    UI <--> Ollama
```

## 2. Background Task Execution (OSINT / Scans)
```mermaid
sequenceDiagram
    participant Admin
    participant Django Web App
    participant Redis Queue
    participant Celery Worker
    participant DB

    Admin->>Django Web App: Start Scan
    Django Web App->>Redis Queue: Queue Task
    Redis Queue->>Celery Worker: Pick up Task
    Celery Worker->>Celery Worker: Run Scan Script
    Celery Worker->>DB: Save Results
    Admin->>Django Web App: View Results
    Django Web App->>DB: Fetch Results
    DB-->>Admin: Display Results
```

## 3. CVE Alerting Flow
```mermaid
flowchart TD
    Task((Cron Job)) --> Fetch[Fetch CVEs from NVD]
    Fetch --> Parse[Parse JSON]
    Parse --> Match[Match vendor technologies]
    
    Match --> DB[(Vendor DB)]
    
    Match -->|Matches found| Alert[Generate Threat Alert]
    Alert --> Notify[Notify Admin]
```

## 4. AI Chatbot Workflow
```mermaid
sequenceDiagram
    participant User
    participant App
    participant DB
    participant Ollama

    User->>App: "Analyze this vulnerability"
    App->>DB: Fetch vulnerability context
    DB-->>App: Context
    App->>Ollama: Prompt + Context
    Ollama-->>App: AI Response
    App-->>User: Show Response
```
