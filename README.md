CTI Dashboard — Project Sentinel

Real-Time Cyber Threat Intelligence Aggregation, Enrichment, Visualization, and Automated Response

Overview

Project Sentinel is a comprehensive Cyber Threat Intelligence (CTI) platform that collects, enriches, analyzes, visualizes, and responds to threat indicators in real time.
It integrates data ingestion, multi-layer enrichment, visualization, and a minimal SOAR (Security Orchestration, Automation, and Response) system in a single self-contained project.

This project focuses on practical CTI operations rather than theoretical models and demonstrates how to build a near-production threat intelligence workflow end-to-end.

Key Features
Real-Time Intelligence Ingestion

Pulls threat indicators (IPs, domains, URLs) from multiple OSINT and blocklist sources.
Supports scheduled ingestion via systemd, with configurable update intervals.

Multi-Stage Enrichment Pipeline

Each indicator is enriched with:

DNS resolution

GeoIP country mapping

Threat scoring

Tag extraction

Type classification

Domain/IP resolution

Historical processing state tracking

The enrichment engine supports both single-threaded and multi-threaded modes for performance.

Interactive Web Dashboard

Built using Flask + Plotly + custom styling.
Features:

Bar charts for threat types

Geographic distribution

Real-time world threat map

Search and filtering

Live indicator table

Detail modal viewer

CSV export functionality

The dashboard design follows a cyber-analysis-focused layout with a clean, minimal, dark theme.

Integrated Lightweight SOAR Engine

The project includes a functional SOAR module capable of:

Blocking indicators via Cloudflare Firewall API

Blocking IPs locally through iptables

Creating investigation cases through TheHive

Managing automation playbooks

Running automated actions with dry-run or confirmed execution

Logging all automation actions for audit and repeatability

A Playbook Manager and Automation Log Viewer are included in the dashboard UI.

Uniqueness of the Project

This project distinguishes itself by combining the following components in a single, fully modular system:

Unified Pipeline (Ingest → Enrich → Visualize → Respond)
Most open-source CTI tools focus on only one part of this chain.
Sentinel combines all stages into one integrated pipeline.

SOAR Integration Without External Dependencies
Instead of relying on heavy SOAR platforms, a minimal, extensible automation system is built from scratch, suitable for learning, demos, and controlled environments.

Customizable Playbook Engine
Users can create, update, and execute playbooks through the UI—something rarely found in CTI dashboards.

Live Threat Map and Real-Time Updating
A dynamic world map visualizing malicious activity based on live feeds and geolocation.

API-Driven Architecture
Every function—from enrichment to playbooks—is accessible via JSON APIs, making it usable in scripts or external SOC tools.

This makes the project suitable for:

Learning CTI operations

SOC analyst workflow simulation

Security engineering practice

Research and academic demonstration

Personal projects and portfolio showcases

Architecture
CTI/
│
├── app.py                    Flask web interface + API
├── live_ingest.py            Scheduled ingestion process
├── feeds.py                  Blocklist and OSINT ingestion
├── enrich.py                 Core enrichment logic
├── collector.py              Ingest + enrich pipeline
├── soar.py                   SOAR automation engine
├── attack_graph.py           MITRE ATT&CK relationship builder
├── db.py                     MongoDB setup and collections
│
├── static/style.css          Dashboard appearance
├── templates/index.html      Main dashboard UI
│
├── etc/systemd/...           systemd unit for live ingestion
├── README.md
└── requirements.txt

Installation
Requirements

Python 3.10+

MongoDB 6+

Linux recommended (for iptables and systemd)

Optional: Cloudflare API token (for blocking)

Optional: TheHive API key (for case creation)

Setup

Clone the repository:

git clone https://github.com/<your-user>/CTI-Sentinel.git
cd CTI-Sentinel


Create virtual environment:

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt


Create a configuration file:

cp config.json.example config.json


Then populate the fields.

Run the dashboard:

python app.py


Access locally at:

http://127.0.0.1:5000


Enable ingestion (optional):

sudo cp etc/systemd/system/cti-live-ingest.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cti-live-ingest


Monitor:

sudo journalctl -u cti-live-ingest -f

Security Notes Before Publishing

Ensure you remove or do not include:

config.json

API keys

GeoIP .mmdb files

Logs directory

pycache and compiled files

systemd service with personal paths

Backup files like *.bak

Use .gitignore to enforce this.

License

MIT License (or set your own if needed).

Acknowledgements

Inspired by modern CTI workflows using OSINT feeds, threat enrichment techniques, and SOAR engineering practices.# CTI-project
