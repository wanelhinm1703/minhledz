#!/usr/bin/env python3
"""
CLI Script: Generate QLoRA Security Fine-Tuning Dataset.
Extracts instruction pairs from SQLite Knowledge Base into Alpaca JSONL format.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure project root is in sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from backend.app.services.dataset_generator import dataset_generator, DEFAULT_OUTPUT_PATH


def main():
    parser = argparse.ArgumentParser(
        description="Generate QLoRA Security Fine-Tuning Dataset (Alpaca JSONL format) from Knowledge Base."
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=str(DEFAULT_OUTPUT_PATH),
        help=f"Output file path (default: {DEFAULT_OUTPUT_PATH})",
    )
    parser.add_argument(
        "--cve-limit",
        type=int,
        default=500,
        help="Maximum number of CVE analysis instruction samples to generate (default: 500)",
    )
    parser.add_argument(
        "--cwe-limit",
        type=int,
        default=52,
        help="Maximum number of CWE remediation instruction samples to generate (default: 52)",
    )
    parser.add_argument(
        "--recon-limit",
        type=int,
        default=100,
        help="Maximum number of Recon synthesis instruction samples to generate (default: 100)",
    )
    parser.add_argument(
        "--preview",
        action="store_true",
        help="Preview the first generated sample in console",
    )

    args = parser.parse_args()

    print(f"[*] Starting QLoRA Security Fine-Tuning Dataset Generation...")
    print(f"    Output Target: {args.output}")
    print(f"    Limits: CVE={args.cve_limit}, CWE={args.cwe_limit}, Recon={args.recon_limit}")

    stats = dataset_generator.build_full_dataset(
        output_file=args.output,
        cve_limit=args.cve_limit,
        cwe_limit=args.cwe_limit,
        recon_limit=args.recon_limit,
    )

    print("\n" + "=" * 65)
    print("      QLORA SECURITY FINE-TUNING DATASET GENERATED")
    print("=" * 65)
    print(f"Output File      : {stats['output_path']}")
    print(f"Format           : {stats['format']}")
    print(f"File Size        : {stats['file_size_kb']} KB")
    print(f"Total Samples    : {stats['total_samples']}")
    print(f"  - CVE Analysis : {stats['cve_samples']} samples")
    print(f"  - CWE Guidance : {stats['cwe_samples']} samples")
    print(f"  - Recon Surface: {stats['recon_samples']} samples")
    print("=" * 65)

    if args.preview or True:
        try:
            with open(stats["output_path"], "r", encoding="utf-8") as f:
                first_line = f.readline()
                if first_line:
                    sample = json.loads(first_line)
                    print("\n[+] Sample Inspection Preview (Item #1):")
                    print(f"--- Instruction ---\n{sample['instruction']}")
                    print(f"\n--- Input ---\n{sample['input']}")
                    print(f"\n--- Output (truncated) ---\n{sample['output'][:250]}...\n")
        except Exception as e:
            print(f"[!] Preview failed: {e}")

    print("[SUCCESS] Dataset ready for QLoRA / Unsloth / Hugging Face SFTTrainer.")


if __name__ == "__main__":
    main()
