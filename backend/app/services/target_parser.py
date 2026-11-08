from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from pydantic import BaseModel

from backend.app.schemas.target import TargetType


class ParsedTarget(BaseModel):
    raw_input: str
    target_type: TargetType
    host: str
    port: int | None = None
    scheme: str | None = None
    path: str | None = None


class TargetParser:
    DOMAIN_REGEX = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    HOSTNAME_REGEX = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*(?:local|internal|corp|lan|localdomain|[a-zA-Z0-9-]+)$"
    )

    @classmethod
    def parse(cls, raw_input: str) -> ParsedTarget:
        text = raw_input.strip()
        if not text:
            raise ValueError("Target input cannot be empty.")

        # 1. URL detection
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", text):
            parsed_url = urlparse(text)
            host = parsed_url.hostname or ""
            port = parsed_url.port
            scheme = parsed_url.scheme.lower()
            path = parsed_url.path or "/"
            return ParsedTarget(
                raw_input=text,
                target_type=TargetType.URL,
                host=host,
                port=port,
                scheme=scheme,
                path=path,
            )

        # 2. CIDR
        if "/" in text:
            try:
                network = ipaddress.ip_network(text, strict=False)
                return ParsedTarget(
                    raw_input=text,
                    target_type=TargetType.CIDR,
                    host=str(network),
                    port=None,
                    scheme=None,
                    path=None,
                )
            except ValueError:
                pass

        # 3. IPv4
        try:
            ip = ipaddress.IPv4Address(text)
            return ParsedTarget(
                raw_input=text,
                target_type=TargetType.IPV4,
                host=str(ip),
                port=None,
                scheme=None,
                path=None,
            )
        except ValueError:
            pass

        # 4. IPv6
        try:
            ip6 = ipaddress.IPv6Address(text)
            return ParsedTarget(
                raw_input=text,
                target_type=TargetType.IPV6,
                host=str(ip6),
                port=None,
                scheme=None,
                path=None,
            )
        except ValueError:
            pass

        # 5. Host:Port (e.g. 10.10.10.20:8080, [::1]:8080)
        host_port_match = re.match(r"^(\[[0-9a-fA-F:]+\]|[^:]+):(\d+)$", text)
        if host_port_match:
            raw_host, raw_port = host_port_match.groups()
            clean_host = raw_host.strip("[]")
            port_num = int(raw_port)
            return ParsedTarget(
                raw_input=text,
                target_type=TargetType.HOST_PORT,
                host=clean_host,
                port=port_num,
                scheme=None,
                path=None,
            )

        # 6. Domain
        if cls.DOMAIN_REGEX.match(text):
            return ParsedTarget(
                raw_input=text,
                target_type=TargetType.DOMAIN,
                host=text.lower(),
                port=None,
                scheme=None,
                path=None,
            )

        # 7. Hostname / Local Domain
        if cls.HOSTNAME_REGEX.match(text):
            return ParsedTarget(
                raw_input=text,
                target_type=TargetType.HOSTNAME,
                host=text.lower(),
                port=None,
                scheme=None,
                path=None,
            )

        return ParsedTarget(
            raw_input=text,
            target_type=TargetType.CUSTOM,
            host=text,
            port=None,
            scheme=None,
            path=None,
        )
