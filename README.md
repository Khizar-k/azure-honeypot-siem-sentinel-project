# Azure Honeypot SIEM Project

This project demonstrates how I deployed a Linux honeypot in Azure, exposed it to the public internet, collected Syslog events, ingested them into Microsoft Sentinel, and analyzed over **139,000+ real-world cyberattacks** using KQL, dashboards, and custom detections.

All images for this project are stored in:

`screenshots/Honeypot-Project/`

---

# Architecture Diagram

The following diagram shows the entire honeypot pipeline, including the Azure VM, NSG, Log Analytics Workspace, Data Collection Rule, Microsoft Sentinel, and the attacker traffic flow from the public internet.

![Architecture Diagram](screenshots/Honeypot-Project/HP-architecture.drawio.png)


---

# Overview

The goals of this project were to:

- Deploy a Linux honeypot VM in Azure  
- Ingest Syslog logs into Log Analytics  
- Connect Microsoft Sentinel as the SIEM  
- Analyze live attack traffic in real time  
- Build custom KQL queries for threat analysis  
- Create a custom SSH brute-force detection rule  
- Document the findings with screenshots  

This project demonstrates skills in cloud security, SIEM operations, Linux logging, KQL, automation, and threat analysis.

---

# Environment Setup

## Azure Virtual Machine
A publicly exposed Linux VM was deployed to attract automated internet attacks. SSH access was confirmed and logs were verified.

![VM Login](screenshots/Honeypot-Project/Screenshot%202025-11-11%20200538.png)

## Azure VM Overview
VM compute details, IP, region, subscription, OS type, and resource configurations were reviewed.

![VM Overview](screenshots/Honeypot-Project/Screenshot%202025-11-12%20001157.png)

---

# Attack Traffic Collection

## Global Attack Map
Within hours of deployment, the honeypot began receiving attacks from around the world.

![Attack Map](screenshots/Honeypot-Project/Screenshot%202025-11-13%20025459.png)

## Attack Details (Countries, IPs, Methods)
Traffic originated from over **20+ countries**, targeting SSH, web services, and other exposed ports.

![Attack Detail](screenshots/Honeypot-Project/Screenshot%202025-11-13%20025531.png)

---

# Network & Security Configuration

## Network Interface
Interface configuration for the honeypot VM.

![Network Interface](screenshots/Honeypot-Project/Screenshot%202025-11-14%20203201.png)

## Network Security Group (NSG)
Inbound rules were intentionally kept open to allow attacker traffic for monitoring.

![NSG](screenshots/Honeypot-Project/Screenshot%202025-11-14%20203228.png)

---

# Defender for Cloud Detection Rule

I created an SSH brute-force detection rule that triggers on repeated failed login attempts from the same IP.

![Detection Rule](screenshots/Honeypot-Project/Screenshot%202025-11-15%20185232.png)

## Rule Enabled
The specific detection rule is activated and monitoring the honeypot.

![Rule Active](screenshots/Honeypot-Project/Screenshot%202025-11-15%20210541.png)

---

# Sentinel Workspace & Data Ingestion

## Sentinel Tables
Over **130+ tables** were available and integrated.

![Tables](screenshots/Honeypot-Project/Screenshot%202025-11-15%20210742.png)

---

# Honeypot Attack Dashboards (Elastic)

## High-Level Dashboard
This dashboard shows total attacks per service, honeypot type, and distribution.

📌 **Total attacks recorded: 139,000+**

![Dashboard](screenshots/Honeypot-Project/Screenshot%202025-11-15%20214101.png)

## Suricata Alerts & Attack Intelligence
Top exploited CVEs, attack signatures, attacker ASN information, and alert types.

![Suricata](screenshots/Honeypot-Project/Screenshot%202025-11-15%20214137.png)

## Honeypot Events by Type & OS Fingerprinting
Breakdown of honeypot interactions and attacker OS fingerprint guesses.

![Event Breakdown](screenshots/Honeypot-Project/Screenshot%202025-11-15%20214209.png)

## Ports, Countries, and Alert Categories
Visualizations of the most attacked ports, countries of origin, and Suricata alert categories.

![Ports and Countries](screenshots/Honeypot-Project/Screenshot%202025-11-15%20214238.png)

---

# Sentinel Syslog Ingestion Verified

Before analysis, I confirmed the Syslog table was receiving data.

![Ingestion](screenshots/Honeypot-Project/Screenshot%202025-11-15%20214909.png)

---

# KQL Queries & Results

## 1. Top Processes by Event Count

```kusto
Syslog
| summarize eventCount = count() by ProcessName
| top 10 by eventCount desc
```

![Top Processes](screenshots/Honeypot-Project/Screenshot%202025-11-15%20215237.png)

---

## 2. Top Attacking IP Addresses

```kusto
Syslog
| extend SourceIP = extract(@"\b(\d{1,3}(\.\d{1,3}){3})\b", 1, SyslogMessage)
| where isnotempty(SourceIP)
| summarize eventCount = count() by SourceIP
| top 10 by eventCount desc
```

![Top IPs](screenshots/Honeypot-Project/Screenshot%202025-11-15%20215308.png)

---

## 3. Severity Level Distribution

```kusto
Syslog
| summarize eventCount = count() by SeverityLevel
| top 10 by eventCount desc
```

![Severity](screenshots/Honeypot-Project/Screenshot%202025-11-15%20215352.png)

---

# Resource Group Overview

All resources used in the honeypot:

![Resource Group](screenshots/Honeypot-Project/Screenshot%202025-11-15%20215519.png)

![Resource Items](screenshots/Honeypot-Project/Screenshot%202025-11-15%20215752.png)

---

# Key Findings

- Over **139,000+ attacks** were recorded across the honeypot in four days.  
- Individual honeypot services received:  
  - **63,000+ Honeyptrap attacks**  
  - **38,000+ SentryPeer attacks**  
  - **29,000+ Cowrie attacks**  
  - 1,000+ attacks on Dionaea and Mailoney  
- Attack traffic originated from **20+ countries**, including the US, China, UK, Germany, Netherlands, France, Hong Kong, and Australia.  
- Suricata logs revealed real exploitation attempts against known CVEs.  
- KQL analysis confirmed attacker IPs, targeted processes, and severity levels.  
- The custom SSH brute-force detection rule successfully triggered.  

---

# Skills Demonstrated

### Cloud
- Azure VM deployment  
- NSG configuration  
- Log Analytics Workspace  
- Data Collection Rules  

### SIEM
- Microsoft Sentinel  
- KQL query development  
- Custom detection rules  
- Log analysis & threat hunting  

### Linux
- SSH access  
- Syslog analysis  
- Process monitoring  

### Security
- Understanding of attacker behavior  
- CVE exploitation detection  
- Suricata IDS analysis  

### Documentation
- Technical reporting  
- Markdown documentation  
- Architecture diagram design  

---

# Project Structure

```text
azure-honeypot-siem-sentinel-project
│
├── screenshots/
│   └── Honeypot-Project/
│       ├── HP-architecture.drawio.png
│       ├── Screenshot 2025-11-11 200538.png
│       ├── Screenshot 2025-11-12 001157.png
│       ├── Screenshot 2025-11-13 025459.png
│       ├── Screenshot 2025-11-13 025531.png
│       ├── Screenshot 2025-11-14 203201.png
│       ├── Screenshot 2025-11-14 203228.png
│       ├── Screenshot 2025-11-15 185232.png
│       ├── Screenshot 2025-11-15 210541.png
│       ├── Screenshot 2025-11-15 210742.png
│       ├── Screenshot 2025-11-15 214101.png
│       ├── Screenshot 2025-11-15 214137.png
│       ├── Screenshot 2025-11-15 214209.png
│       ├── Screenshot 2025-11-15 214238.png
│       ├── Screenshot 2025-11-15 214909.png
│       ├── Screenshot 2025-11-15 215237.png
│       ├── Screenshot 2025-11-15 215308.png
│       ├── Screenshot 2025-11-15 215352.png
│       ├── Screenshot 2025-11-15 215519.png
│       └── Screenshot 2025-11-15 215752.png
│
└── README.md
```

---
