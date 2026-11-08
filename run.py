#!/usr/bin/env python3
import os
import pathlib
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parent

# Auto-detect and switch to project virtualenv if running with global python
if sys.prefix == sys.base_prefix:
    venv_python = root / "venv" / "bin" / "python"
    if not venv_python.exists():
        venv_python = root / "venv" / "Scripts" / "python.exe"
    if venv_python.exists():
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root)
        res = subprocess.run([str(venv_python), str(root / "run.py")] + sys.argv[1:], env=env)
        sys.exit(res.returncode)

if str(root) not in sys.path:
    sys.path.insert(0, str(root))


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print("AI-Pentest Copilot - Universal CLI Runner")
        print("  python run.py setup")
        print("  python run.py scan TARGET=<target>")
        print("  python run.py pipeline TARGET=<target> [--tools=all|network|web]")
        print("  python run.py ingest")
        print("  python run.py vector-sync")
        print("  python run.py vector-stats")
        print("  python run.py intel-sync")
        print("  python run.py graph-rag TARGET=<target>")
        print("  python run.py assess TARGET=<target>")
        print("  python run.py pdf TARGET=<target>")
        print("  python run.py generate-dataset [--output=...]")
        print("  python run.py kb-stats")
        print("  python run.py catalog")
        print("  python run.py docker-build")
        print("  python run.py docker-up")
        print("  python run.py docker-down")
        print("  python run.py docker-tools")
        print("  python run.py test")
        print("  python run.py dev")
        return

    cmd = sys.argv[1]
    if cmd == "setup":
        res = subprocess.run(
            [sys.executable, str(root / "toolkit" / "scripts" / "init_dirs.py")]
        )
        sys.exit(res.returncode)
    elif cmd in ("scan", "pipeline"):
        target = None
        tools_arg = None
        for arg in sys.argv[2:]:
            if arg.startswith("TARGET="):
                target = arg.split("=", 1)[1]
            elif arg.startswith("--tools="):
                tools_arg = arg
            elif not target and not arg.startswith("-"):
                target = arg
            elif arg.startswith("-"):
                tools_arg = arg
        if not target:
            print(
                f"ERROR: TARGET is required. Example: python run.py {cmd} TARGET=192.168.56.101"
            )
            sys.exit(1)

        script = "targets.py" if cmd == "scan" else "pipeline_runner.py"
        args = ["scan", "--target", target] if cmd == "scan" else [target]
        if tools_arg and cmd == "pipeline":
            args.append(tools_arg)
        res = subprocess.run(
            [sys.executable, str(root / "toolkit" / "scripts" / script)] + args
        )
        sys.exit(res.returncode)
    elif cmd == "ingest":
        update_flag = ["--update"] if "--update" in sys.argv else []
        res = subprocess.run(
            [sys.executable, "-m", "backend.app.ingest.run"] + update_flag
        )
        if res.returncode == 0:
            print("[*] Auto-synchronizing SQLite into Vector Store & FTS5...")
            from backend.app.services.vector_store import vector_store
            from backend.app.services.fts5_search import fts5_search
            vector_store.sync_from_sqlite()
            fts5_search.rebuild_index()
            print("[OK] Vector Store & FTS5 synchronization completed.")
        sys.exit(res.returncode)
    elif cmd == "vector-sync":
        from backend.app.services.vector_store import vector_store
        from backend.app.services.fts5_search import fts5_search
        print("[*] Syncing SQLite KB into Vector Store & FTS5...")
        v_res = vector_store.sync_from_sqlite()
        f_res = fts5_search.rebuild_index()
        print(f"[OK] Vector Synced: {v_res} | FTS5 Rebuilt: {f_res}")
        sys.exit(0)
    elif cmd == "vector-stats":
        from backend.app.services.vector_store import vector_store
        stats = vector_store.get_stats()
        print("\n=== VECTOR DATABASE STATISTICS (ChromaDB / VectorStore) ===")
        print(f"Engine       : {stats['engine']}")
        print(f"Storage Path : {stats['storage_path']}")
        print(f"Total Vectors: {stats['total_vectors']}")
        for c_name, c_cnt in stats['collections'].items():
            print(f"  - {c_name:<18}: {c_cnt} vectors")
        print("============================================================\n")
        sys.exit(0)
    elif cmd == "intel-sync":
        from backend.app.services.threat_intel_feed import threat_intel_feed
        print("[*] Running Automated Threat Intelligence Ingestion Feed...")
        res = threat_intel_feed.run_full_sync()
        print(f"[OK] Threat Intel Sync Completed in {res['duration_seconds']}s")
        print(f"     Active CISA KEVs: {res['cisa_kev_active']}")
        print(f"     Vectors Synced  : {res['vector_store_synced']}")
        sys.exit(0)
    elif cmd == "graph-rag":
        target = None
        for arg in sys.argv[2:]:
            if arg.startswith("TARGET="):
                target = arg.split("=", 1)[1]
            elif not target and not arg.startswith("-"):
                target = arg
        if not target:
            target = "192.168.100.153"
        from backend.app.services.graph_rag import graph_rag
        print(f"\n[*] Querying Graph RAG Attack Chains for target: {target}")
        chains = graph_rag.get_attack_chains_for_target(target)
        print(f"[+] Total Causal Attack Chains: {len(chains)}")
        for idx, ch in enumerate(chains, 1):
            print(f"\n--- Attack Chain #{idx} [{ch['risk_level']}] ({ch['initial_finding']}) ---")
            for st in ch['chain_steps']:
                desc = st.get('technique', st.get('entity', ''))
                print(f"  Step {st['step']} [{st['stage']}]: {desc}")
        sys.exit(0)
    elif cmd == "assess":
        target = None
        for arg in sys.argv[2:]:
            if arg.startswith("TARGET="):
                target = arg.split("=", 1)[1]
            elif not target and not arg.startswith("-"):
                target = arg
        if not target:
            target = "192.168.100.153"
        from backend.app.services.agents.orchestrator import agent_orchestrator
        print(f"\n[*] Launching Collaborative Multi-Agent Assessment for target: {target}")
        assessment = agent_orchestrator.run_collaborative_assessment(target)
        print(f"\n[+] Multi-Agent Assessment Complete:")
        print(f"    Target ID          : {assessment.target_id}")
        print(f"    Executive Summary  : {assessment.executive_summary[:160]}...")
        print(f"\n--- Sub-Agent Findings Breakdown ---")
        print(f"  * Recon Discovered Services: {len(assessment.recon_analysis.discovered_services)} (Tools: {len(assessment.recon_analysis.tools_analyzed)})")
        print(f"  * Threat Intel Matches     : {len(assessment.threat_intel.matches)} (Highest CVSS: {assessment.threat_intel.highest_cvss}, KEV: {assessment.threat_intel.kev_count})")
        print(f"  * Safe Verification Plans  : {len(assessment.verification_plans)}")
        if assessment.compliance_report:
            cr = assessment.compliance_report
            print(f"  * Compliance Scorecard     : {cr.overall_compliance_score}% ({cr.overall_status})")
            for std_name, sc in cr.scorecards.items():
                print(f"    - {std_name:<18}: {sc.compliance_score}% [{sc.status}] (Violations: {sc.violations_count})")
            print(f"    - Total Violations       : {len(cr.violations)}")
        sys.exit(0)
    elif cmd == "pdf":
        target = None
        for arg in sys.argv[2:]:
            if arg.startswith("TARGET="):
                target = arg.split("=", 1)[1]
            elif not target and not arg.startswith("-"):
                target = arg
        if not target:
            target = "192.168.100.153"
        from backend.app.services.report_generator import report_generator
        print(f"\n[*] Generating Enterprise-grade Audit PDF Report for target: {target}")
        rep = report_generator.generate_report(target)
        pdf_path = rep.get("pdf_path")
        print(f"[OK] Generated Audit PDF Report successfully: {pdf_path}")
        print(f"     Target ID          : {rep.get('target_id')}")
        print(f"     HTML Report        : {rep.get('html_path')}")
        print(f"     SARIF Report       : {rep.get('sarif_path')}")
        sys.exit(0)
    elif cmd == "generate-dataset":
        res = subprocess.run([sys.executable, str(root / "scripts" / "generate_finetune_dataset.py")] + sys.argv[2:])
        sys.exit(res.returncode)
    elif cmd == "kb-stats":
        res = subprocess.run(
            [sys.executable, str(root / "backend" / "app" / "storage" / "db.py")]
        )
        sys.exit(res.returncode)
    elif cmd == "catalog":
        from backend.app.services.tool_registry import tool_registry

        tools = tool_registry.list_tools()
        avail = tool_registry.get_all_availability()
        installed_count = sum(1 for a in avail.values() if a.installed)
        print(f"\n[+] Total Registered Tools: {len(tools)} (Installed on host: {installed_count})")
        print(f"[+] Total Unique Tags: {len(tool_registry.list_tags())}\n")
        print(f"{'ID':<15} {'NAME':<20} {'CATEGORY':<15} {'STATUS':<12} {'TAGS'}")
        print("-" * 80)
        for t in tools:
            st = avail.get(t.tool_id)
            status_label = "INSTALLED" if (st and st.installed) else "MISSING"
            print(f"{t.tool_id:<15} {t.name:<20} {t.category:<15} {status_label:<12} {', '.join(t.tags[:3])}")
        print("")
        sys.exit(0)
    elif cmd == "docker-build":
        print("[*] Building AI-Pentest Tools Sandbox Docker Image...")
        res = subprocess.run(
            [
                "docker",
                "build",
                "-t",
                "ai-pentest-tools:latest",
                "-f",
                str(root / "infra" / "docker" / "Dockerfile.tools"),
                str(root),
            ]
        )
        sys.exit(res.returncode)
    elif cmd == "docker-up":
        print("[*] Starting Full-Stack AI-Pentest Copilot in Docker (Backend, Frontend, Tools)...")
        res = subprocess.run(["docker", "compose", "up", "--build", "-d"])
        sys.exit(res.returncode)
    elif cmd == "docker-down":
        print("[*] Stopping all Docker containers...")
        res = subprocess.run(["docker", "compose", "down"])
        sys.exit(res.returncode)
    elif cmd == "docker-tools":
        print("[*] Starting isolated Pentest Tools Sandbox container...")
        res = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(root / "infra" / "docker" / "docker-compose.tools.yml"),
                "up",
                "-d",
            ]
        )
        sys.exit(res.returncode)
    elif cmd == "test":
        res = subprocess.run([sys.executable, "-m", "pytest", "backend/tests", "-v"])
        sys.exit(res.returncode)
    elif cmd == "dev":
        res = subprocess.run(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "backend.app.main:app",
                "--reload",
                "--port",
                "8000",
            ]
        )
        sys.exit(res.returncode)
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
