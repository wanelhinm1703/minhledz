#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import pathlib
import sys
import xml.etree.ElementTree as ET
import jsonschema


class NmapParser:
    @classmethod
    def parse_xml_file(
        cls,
        xml_path: pathlib.Path,
        scan_metadata: dict | None = None,
        schema_path: pathlib.Path | None = None,
    ) -> dict:
        if not xml_path.exists():
            raise FileNotFoundError(f"Raw Nmap XML file not found at: {xml_path}")

        tree = ET.parse(xml_path)
        root = tree.getroot()

        tool = root.attrib.get("scanner", "nmap")
        cmd = root.attrib.get("args", "")

        meta = scan_metadata or {}
        structured_meta = {
            "tool": tool,
            "target": meta.get("target", "unknown"),
            "command": meta.get("command", cmd),
            "arguments": meta.get("arguments", ""),
            "timestamp": meta.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "duration_seconds": float(meta.get("duration", 0.0)),
            "exit_code": int(meta.get("exit_code", 0)),
        }

        hosts = []
        for host_node in root.findall("host"):
            status_node = host_node.find("status")
            status_obj = {
                "state": status_node.attrib.get("state", "unknown") if status_node is not None else "unknown",
                "reason": status_node.attrib.get("reason", "") if status_node is not None else "",
            }

            addresses = {}
            for addr in host_node.findall("address"):
                addr_type = addr.attrib.get("addrtype")
                if addr_type:
                    addresses[addr_type] = addr.attrib.get("addr", "")

            hostnames = []
            hostnames_node = host_node.find("hostnames")
            if hostnames_node is not None:
                for hn in hostnames_node.findall("hostname"):
                    name = hn.attrib.get("name")
                    if name:
                        hostnames.append(name)

            ports = []
            ports_node = host_node.find("ports")
            if ports_node is not None:
                for port_node in ports_node.findall("port"):
                    portid = int(port_node.attrib.get("portid", 0))
                    protocol = port_node.attrib.get("protocol", "tcp")

                    state_node = port_node.find("state")
                    state = state_node.attrib.get("state", "closed") if state_node is not None else "closed"
                    reason = state_node.attrib.get("reason", "") if state_node is not None else ""

                    service_obj = {}
                    service_node = port_node.find("service")
                    if service_node is not None:
                        cpes = [c.text for c in service_node.findall("cpe") if c.text]
                        service_obj = {
                            "name": service_node.attrib.get("name", ""),
                            "product": service_node.attrib.get("product", ""),
                            "version": service_node.attrib.get("version", ""),
                            "extrainfo": service_node.attrib.get("extrainfo", ""),
                            "cpe": cpes,
                        }

                    scripts = []
                    for script_node in port_node.findall("script"):
                        scripts.append({
                            "id": script_node.attrib.get("id", ""),
                            "output": script_node.attrib.get("output", ""),
                        })

                    ports.append({
                        "portid": portid,
                        "protocol": protocol,
                        "state": state,
                        "reason": reason,
                        "service": service_obj,
                        "scripts": scripts,
                    })

            hosts.append({
                "status": status_obj,
                "addresses": addresses,
                "hostnames": hostnames,
                "ports": ports,
            })

        result = {
            "scan_metadata": structured_meta,
            "hosts": hosts,
        }

        if schema_path and schema_path.exists():
            schema_data = json.loads(schema_path.read_text(encoding="utf-8"))
            jsonschema.validate(instance=result, schema=schema_data)

        return result


def main():
    parser = argparse.ArgumentParser(description="Parse Nmap XML to Structured JSON")
    parser.add_argument("--xml", required=True, help="Path to raw nmap.xml")
    parser.add_argument("--output", required=True, help="Path to structured output.json")
    parser.add_argument("--schema", help="Path to nmap_result.schema.json")
    args = parser.parse_args()

    xml_p = pathlib.Path(args.xml)
    out_p = pathlib.Path(args.output)
    schema_p = pathlib.Path(args.schema) if args.schema else None

    structured = NmapParser.parse_xml_file(xml_p, schema_path=schema_p)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    print(f"Structured Nmap JSON written and validated at: {out_p}")


if __name__ == "__main__":
    main()
