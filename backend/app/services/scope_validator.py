from __future__ import annotations

import fnmatch
import ipaddress
import os
from typing import List, Optional
from backend.app.schemas.target import ScopeDecision, Target


class ScopeViolation(Exception):
    pass


class ScopeValidator:
    DEFAULT_ALLOWED_SCOPES = [
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "127.0.0.0/8",
        "::1/128",
        "*.local",
        "localhost",
    ]

    def __init__(self, allowed_scopes: Optional[List[str]] = None):
        env_scopes = os.getenv("ALLOWED_SCOPES")
        if env_scopes:
            self.allowed_scopes = [s.strip() for s in env_scopes.split(",") if s.strip()]
        elif allowed_scopes is not None:
            self.allowed_scopes = allowed_scopes
        else:
            self.allowed_scopes = list(self.DEFAULT_ALLOWED_SCOPES)

    def is_ip_in_network(self, ip_str: str, net_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            net = ipaddress.ip_network(net_str, strict=False)
            return ip in net
        except ValueError:
            return False

    def is_network_contained(self, cidr_str: str, net_str: str) -> bool:
        try:
            target_net = ipaddress.ip_network(cidr_str, strict=False)
            allowed_net = ipaddress.ip_network(net_str, strict=False)
            return target_net.subnet_of(allowed_net)
        except (ValueError, TypeError, AttributeError):
            return False

    def validate(self, target: Target) -> ScopeDecision:
        host = target.host
        port = target.port

        if port and target.scope.forbidden_ports and port in target.scope.forbidden_ports:
            return ScopeDecision(
                allowed=False,
                reason=f"Port {port} is explicitly listed in forbidden_ports.",
                target_host=host,
                target_port=port,
            )

        for rule in self.allowed_scopes:
            if "/" in rule:
                if "/" in host:
                    if self.is_network_contained(host, rule):
                        return ScopeDecision(
                            allowed=True,
                            reason=f"Target network '{host}' is authorized under allowed scope '{rule}'.",
                            matched_rule=rule,
                            target_host=host,
                            target_port=port,
                        )
                elif self.is_ip_in_network(host, rule):
                    return ScopeDecision(
                        allowed=True,
                        reason=f"Target IP '{host}' is authorized under allowed subnet '{rule}'.",
                        matched_rule=rule,
                        target_host=host,
                        target_port=port,
                    )
            elif host.lower() == rule.lower():
                return ScopeDecision(
                    allowed=True,
                    reason=f"Target host '{host}' exactly matches allowed rule '{rule}'.",
                    matched_rule=rule,
                    target_host=host,
                    target_port=port,
                )
            elif fnmatch.fnmatch(host.lower(), rule.lower()):
                return ScopeDecision(
                    allowed=True,
                    reason=f"Target host '{host}' matches allowed wildcard rule '{rule}'.",
                    matched_rule=rule,
                    target_host=host,
                    target_port=port,
                )

        return ScopeDecision(
            allowed=False,
            reason=f"Target '{host}' is OUT OF SCOPE. It does not match any configured allowed scopes: {', '.join(self.allowed_scopes)}.",
            matched_rule=None,
            target_host=host,
            target_port=port,
        )
