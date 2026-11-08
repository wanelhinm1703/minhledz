from __future__ import annotations

import ipaddress
from typing import Any

from backend.app.schemas.target import TargetType, ValidationResult
from backend.app.services.target_parser import ParsedTarget


class TargetValidator:
    VALID_SCHEMES = {"http", "https", "ssh", "ftp", "tcp", "udp"}

    @classmethod
    def validate(
        cls, parsed: ParsedTarget, normalized: dict[str, Any]
    ) -> ValidationResult:
        errors = []
        target_type = parsed.target_type
        host = normalized.get("host", "")
        port = normalized.get("port")
        scheme = normalized.get("scheme")

        if port is not None:
            if not isinstance(port, int) or port < 1 or port > 65535:
                errors.append(
                    f"Invalid port number: {port}. Port must be between 1 and 65535."
                )

        if scheme is not None and scheme not in cls.VALID_SCHEMES:
            errors.append(
                f"Unsupported scheme '{scheme}'. Supported schemes: {', '.join(sorted(cls.VALID_SCHEMES))}."
            )

        if target_type == TargetType.IPV4:
            try:
                ipaddress.IPv4Address(host)
            except ValueError as e:
                errors.append(f"Invalid IPv4 address '{host}': {e!s}")

        elif target_type == TargetType.IPV6:
            try:
                ipaddress.IPv6Address(host)
            except ValueError as e:
                errors.append(f"Invalid IPv6 address '{host}': {e!s}")

        elif target_type == TargetType.CIDR:
            try:
                ipaddress.ip_network(host, strict=False)
            except ValueError as e:
                errors.append(f"Invalid CIDR block '{host}': {e!s}")

        elif target_type == TargetType.DOMAIN:
            if len(host) > 253:
                errors.append("Domain name exceeds maximum length of 253 characters.")
            for label in host.split("."):
                if not label or len(label) > 63:
                    errors.append(
                        f"Domain label '{label}' is empty or exceeds 63 characters."
                    )

        elif target_type == TargetType.CUSTOM:
            errors.append(
                f"Unable to recognize target type for input '{parsed.raw_input}'."
            )

        return ValidationResult(
            is_valid=len(errors) == 0,
            target_type=target_type,
            errors=errors,
            details=normalized,
        )
