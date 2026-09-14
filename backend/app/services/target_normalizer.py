from __future__ import annotations

import ipaddress
from backend.app.schemas.target import TargetType
from backend.app.services.target_parser import ParsedTarget


class TargetNormalizer:
    @classmethod
    def normalize(cls, parsed: ParsedTarget) -> dict:
        host = parsed.host.strip()
        port = parsed.port
        scheme = parsed.scheme.lower() if parsed.scheme else None
        path = parsed.path

        if parsed.target_type == TargetType.CIDR:
            try:
                network = ipaddress.ip_network(host, strict=False)
                normalized_value = str(network)
                host = normalized_value
            except ValueError:
                normalized_value = host

        elif parsed.target_type == TargetType.URL:
            host = host.lower()
            if not port:
                port = 443 if scheme == "https" else 80
            path_str = path if path and path != "/" else ""
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                normalized_value = f"{scheme}://{host}{path_str or '/'}"
            else:
                normalized_value = f"{scheme}://{host}:{port}{path_str or '/'}"

        elif parsed.target_type == TargetType.HOST_PORT:
            host = host.lower()
            normalized_value = f"{host}:{port}"

        elif parsed.target_type in (TargetType.DOMAIN, TargetType.HOSTNAME):
            host = host.lower().rstrip(".")
            normalized_value = host

        elif parsed.target_type in (TargetType.IPV4, TargetType.IPV6):
            normalized_value = host

        else:
            normalized_value = host

        return {
            "raw_input": parsed.raw_input,
            "normalized_value": normalized_value,
            "host": host,
            "port": port,
            "scheme": scheme,
            "path": path,
            "type": parsed.target_type,
        }
