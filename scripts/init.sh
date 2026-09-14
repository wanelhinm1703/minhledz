#!/usr/bin/env bash
# scripts/init.sh - Initialize 8-layer directory structure for AI-Pentest Copilot
set -euo pipefail

echo "==> Initializing AI-Pentest Copilot directory structure..."

mkdir -p backend/app/{api,ws,core,services,storage,schemas,ingest,eval,utils}
mkdir -p backend/tests
mkdir -p frontend/src/{components/{Layout,Explorer,Editor,Target,Chat,Terminal,Settings,common},pages,hooks,api,store,types,lib,styles}
mkdir -p security/{docs,schemas,datasets/{samples,expected,knowledge},evaluation,knowledge,attack-plans}
mkdir -p toolkit/{00-meta/templates,01-targets/{campaigns/lab-local/targets,presets,templates,registry},02-passive,03-network/scans,04-web,05-vulnerability,06-service-enum,07-cloud-secret,08-manual,09-analysis,10-findings,11-plans,12-reports,tools/network,scripts,wordlists,configs,logs,tmp}
mkdir -p shared/{types,api,websocket,constants}
mkdir -p docs infra/docker scripts

echo "==> 8-layer directory structure initialized successfully."
