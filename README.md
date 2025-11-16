# Azure Honeypot SIEM Project

This project shows how I deployed a Linux virtual machine in Azure, forwarded Syslog events into Microsoft Sentinel, and used KQL to analyze real attack traffic. The VM was exposed to the internet for several days, generating authentic logs from automated scans and probing activity.

All screenshots used in this project are stored in:

`screenshots/Honeypot-Project/`

---

# Overview

The goals of this project were to:

* Deploy a Linux VM in Azure  
* Enable Syslog forwarding into a Log Analytics Workspace  
* Connect Microsoft Sentinel for SIEM monitoring  
* Use KQL queries to break down attack behavior  
* Document the analysis with screenshots  

This project demonstrates core security skills including log analysis, SIEM operations, cloud monitoring, and KQL.

---

# Environment Setup

### Azure VM

A Linux virtual machine was deployed with inbound access to allow internet traffic. SSH was used to confirm system activity.

### Log Analytics Workspace

A Data Collection Rule was configured to ingest Syslog events into the workspace.

### Microsoft Sentinel

Sentinel was connected to the workspace for querying and visualizing logged events.

---

# KQL Queries and Screenshots

Below are the key queries used for analysis along with the corresponding Sentinel screenshots.

---

## Query One  
### Top processes by event count

```kusto
Syslog
| summarize eventCount = count() by ProcessName
| top 10 by eventCount desc
