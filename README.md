# ScanForge

ScanForge is a MERN-based network reconnaissance and risk visibility platform built for fast, visual analysis of live hosts. It performs multi-target port scanning, banner capture, Shodan CVE enrichment, and stores historical scans with timestamps for repeatability and comparison. The UI is designed as a control room for technical audits and academic demonstrations.

## Features

- Multi-target scanning: IPs, domains, and CIDR ranges in one run.
- Live detection: Ping + TCP fallback before scanning.
- Port scanning with banner capture (TCP).
- DNS version probes on TCP/UDP 53 for authoritative server banners.
- Shodan CVE enrichment with MITRE + NVD links.
- Optional NVD CVSS fallback for missing scores.
- Persistent scan history stored in MongoDB.
- Export results to JSON/CSV.
- Queue status panel for long-running scans.

## Tech Stack

- MongoDB for history and scan artifacts
- Express + Node.js backend
- React + Vite frontend
- Shodan API integration
- NVD API fallback (optional)

## Architecture Overview

ScanForge runs as a single service: the Node/Express backend serves the API and the built React UI. The client submits scan jobs to the API, and the server executes scanning and enrichment, then stores results in MongoDB for later review.

## How It Works

1. Input targets: IPs, domains, or CIDRs (one per line).
2. Resolve to IPs and run live checks (ping with TCP fallback).
3. Scan configured ports and grab service banners.
4. Enrich with Shodan CVEs and optional NVD CVSS fallback.
5. Save results in MongoDB and render history in the UI.

## Project Structure

```
ScanForge/
  client/      # React UI
  server/      # Express API
```

## Local Run (Single Service)

### 1) Build the client

```
cd ScanForge/client
npm install
npm run build
```

### 2) Start the server

```
cd ScanForge/server
npm install
SHODAN_API_KEY=YOUR_KEY MONGO_URI=mongodb://localhost:27017/opencode npm start
```

Open:

```
http://localhost:5050
```

## Environment Variables

- `MONGO_URI` (required)
- `SHODAN_API_KEY` (required for CVE enrichment)
- `NVD_API_KEY` (optional, improves CVSS accuracy + rate limits)

## Deployment (Render, Single Service)

- Root Directory: `ScanForge/server`
- Build Command:

```
cd server && npm install && cd ../client && npm install && npm run build
```

- Start Command:

```
cd server && npm start
```

Set the environment variables in Render’s dashboard.

## Exports

- JSON: `/api/scans/:id/export?format=json`
- CSV: `/api/scans/:id/export?format=csv`

## AI and Intelligent Analysis

ScanForge is designed to be extended with AI-assisted analysis. The AI layer can summarize scan results, prioritize vulnerabilities based on risk, and produce executive-ready reports automatically. This makes ScanForge ideal for academic demonstrations of applied AI in cybersecurity.

## Future Functionality

- AI-based misconfiguration detection (open admin panels, default credentials, unsafe headers)
- AI-driven remediation suggestions for exposed services
- Automatic detection of weak TLS/SSL configurations
- Asset change tracking across scan history
- Service fingerprinting with ML-based heuristics
- Risk scoring per host based on exposure + CVE severity
- Report generator (PDF/Docx) with charts and findings
- Multi-user authentication and role-based access

## Disclaimer

Use ScanForge only on systems you own or have explicit permission to test.
