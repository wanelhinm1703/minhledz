from __future__ import annotations

from datetime import datetime, timezone
import json
import sqlite3
from typing import List, Dict, Any


# Authoritative CWE Definitions covering OWASP Top 10 & CWE Top 25
CORE_CWES = [
    ("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", "The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize sequences such as '..' that can resolve to a location that is outside of that directory.", "High", "Use path canonicalization and whitelist allowed directory paths.", "CWE-20"),
    ("CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.", "High", "Context-aware output encoding, Content Security Policy (CSP).", "CWE-74"),
    ("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "The product constructs all or part of an SQL command using externally-influenced input, but does not neutralize special elements that could modify the intended SQL command.", "High", "Use parameterized queries / prepared statements.", "CWE-74"),
    ("CWE-78", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", "The product constructs all or part of an OS command using externally-influenced input, allowing execution of arbitrary system commands.", "High", "Avoid passing user input to shell; use safe APIs with argument lists.", "CWE-74"),
    ("CWE-287", "Improper Authentication", "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.", "Medium", "Implement multi-factor authentication, secure password hashing.", "CWE-284"),
    ("CWE-306", "Missing Authentication for Critical Function", "The software does not perform any authentication for functionality that requires a provable user identity.", "High", "Ensure all sensitive endpoints enforce session verification.", "CWE-287"),
    ("CWE-352", "Cross-Site Request Forgery (CSRF)", "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.", "Medium", "Use anti-CSRF tokens (SameSite cookie attributes, Double Submit Cookie).", "CWE-345"),
    ("CWE-434", "Unrestricted Upload of File with Dangerous Type", "The software allows the attacker to upload or transfer files of dangerous types that can be directly processed within the product's environment.", "High", "Validate file extensions against whitelist; store uploads outside web root.", "CWE-20"),
    ("CWE-502", "Deserialization of Untrusted Data", "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.", "High", "Avoid deserializing untrusted payloads; use safe data formats like JSON.", "CWE-20"),
    ("CWE-862", "Missing Authorization", "The software does not perform an authorization check when an actor attempts to access a resource or perform an action.", "High", "Implement role-based access control (RBAC) at controller level.", "CWE-285"),
    ("CWE-863", "Incorrect Authorization", "The software performs an authorization check, but it is incorrectly implemented.", "High", "Centralize authorization logic and enforce least privilege.", "CWE-285"),
    ("CWE-918", "Server-Side Request Forgery (SSRF)", "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but does not sufficiently verify that the request target is safe.", "High", "Sanitize and validate URL destinations against strict whitelist.", "CWE-20"),
    ("CWE-94", "Improper Control of Generation of Code ('Code Injection')", "The software constructs all or part of a code segment using externally-influenced input.", "High", "Refrain from eval() and dynamic code compilation.", "CWE-74"),
    ("CWE-77", "Improper Neutralization of Special Elements used in a Command ('Command Injection')", "The software constructs all or part of a command using externally-influenced input.", "High", "Use parameter binding and whitelist characters.", "CWE-74"),
    ("CWE-20", "Improper Input Validation", "The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.", "High", "Implement strict schema validation on all incoming inputs.", "CWE-707"),
    ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor", "The product exposes sensitive information to an actor who is not explicitly authorized to have access to that information.", "Medium", "Audit error messages, logs, and debug endpoints.", "CWE-668"),
    ("CWE-319", "Cleartext Transmission of Sensitive Information", "The software transmits sensitive data in cleartext in a communication channel that can be sniffed by unauthorized actors.", "Medium", "Enforce TLS 1.3 / HTTPS everywhere.", "CWE-311"),
    ("CWE-384", "Session Fixation", "The software does not assign a new session ID upon successful user authentication.", "Medium", "Regenerate session identifiers upon login.", "CWE-287"),
    ("CWE-522", "Insufficiently Protected Credentials", "The product transmits or stores authentication credentials without adequate protection.", "High", "Use Argon2id or bcrypt with strong work factor.", "CWE-255"),
    ("CWE-601", "URL Redirection to Untrusted Site ('Open Redirect')", "A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect.", "Low", "Use fixed redirect mappings or validate against domain whitelist.", "CWE-20"),
    ("CWE-798", "Use of Hard-coded Credentials", "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication.", "High", "Store secrets in secure vault / environment variables.", "CWE-255"),
    ("CWE-269", "Improper Privilege Management", "The software does not properly assign, modify, track, or verify privileges for an actor.", "High", "Enforce separation of duties and least privilege.", "CWE-284"),
    ("CWE-119", "Improper Restriction of Operations within the Bounds of a Memory Buffer", "The software performs operations on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary.", "High", "Use memory-safe languages or strict bounds checking.", "CWE-118"),
    ("CWE-125", "Out-of-bounds Read", "The software reads data past the end, or before the beginning, of the intended buffer.", "Medium", "Enforce buffer length validation.", "CWE-119"),
    ("CWE-787", "Out-of-bounds Write", "The software writes data past the end, or before the beginning, of the intended buffer.", "High", "Validate indices and buffer capacities.", "CWE-119"),
    ("CWE-416", "Use After Free", "Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code.", "High", "Set pointers to NULL after freeing; utilize smart pointers.", "CWE-119"),
    ("CWE-476", "NULL Pointer Dereference", "A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL.", "Medium", "Check pointer nullability before dereference.", "CWE-703"),
    ("CWE-190", "Integer Overflow or Wraparound", "The software performs a calculation that can produce an integer overflow or wraparound.", "Medium", "Use checked arithmetic and saturated math.", "CWE-682"),
    ("CWE-362", "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')", "The software contains a code sequence that can run concurrently with other code, and the code sequence requires temporary, exclusive access to a shared resource.", "Medium", "Implement mutex locking and atomic operations.", "CWE-662"),
    ("CWE-400", "Uncontrolled Resource Consumption", "The software does not properly control the allocation and maintenance of a limited resource.", "Medium", "Enforce rate limiting, timeouts, and resource quotas.", "CWE-707"),
    ("CWE-611", "Improper Restriction of XML External Entity Reference ('XXE')", "The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control.", "High", "Disable DTD and external entity resolution in XML parsers.", "CWE-20"),
    ("CWE-91", "XML Injection (aka Blind XPath Injection)", "The software does not properly neutralize XML special characters.", "Medium", "Use parameterized XPath queries.", "CWE-74"),
    ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm", "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.", "Medium", "Adopt modern cryptographic standards (AES-GCM, SHA-256).", "CWE-310"),
    ("CWE-330", "Use of Insufficiently Random Values", "The software uses insufficiently random values in a security context where unpredictable values are needed.", "High", "Use cryptographically secure pseudorandom number generators (CSPRNG).", "CWE-310"),
    ("CWE-338", "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)", "The product uses a Pseudo-Random Number Generator (PRNG) in a security context, but the algorithm's state can be predicted.", "High", "Utilize secrets module / /dev/urandom.", "CWE-330"),
    ("CWE-295", "Improper Certificate Validation", "The software does not validate, or incorrectly validates, a certificate.", "High", "Enforce strict TLS certificate chain validation.", "CWE-297"),
    ("CWE-640", "Weak Password Recovery Mechanism for Forgotten Password", "The software contains a mechanism for users to recover or reset their passwords, but the mechanism is not sufficiently secure.", "Medium", "Send time-limited cryptographic reset tokens via verified channels.", "CWE-287"),
    ("CWE-307", "Improper Restriction of Excessive Authentication Attempts", "The software does not implement suitable limits for authentication attempts.", "High", "Implement account lockouts and IP rate limiting.", "CWE-306"),
    ("CWE-732", "Incorrect Permission Assignment for Critical Resource", "The product specifies permissions for a security-critical resource in a way that allows unintended actors to read or modify the resource.", "High", "Enforce POSIX 0600/0700 file permissions.", "CWE-284"),
    ("CWE-276", "Incorrect Default Permissions", "During installation or execution, default permissions are set to permit unauthorized access.", "Medium", "Ensure default permissions follow least-privilege.", "CWE-732"),
    ("CWE-284", "Improper Access Control", "The software does not restrict or incorrectly restricts access to a resource from an unauthorized actor.", "High", "Implement unified policy enforcement point.", "CWE-693"),
    ("CWE-668", "Exposure of Resource to Wrong Sphere", "The product exposes a resource to the wrong control sphere, providing unintended access.", "Medium", "Separate internal resources from public boundaries.", "CWE-284"),
    ("CWE-707", "Improper Neutralization in Data Extraction/Transformation", "The product does not properly neutralize elements when extracting, transforming, or generating data.", "High", "Apply strict data encoding per target format.", "CWE-20"),
    ("CWE-74", "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')", "The software constructs all or part of a command, data structure, or record using externally-influenced input.", "High", "Separate code from data using parameterization.", "CWE-707"),
    ("CWE-255", "Credentials Management Errors", "Weaknesses in this category are related to the management of credentials.", "High", "Implement rigorous secret management lifecycle.", "CWE-284"),
    ("CWE-285", "Improper Authorization", "The software does not perform or incorrectly performs an authorization check.", "High", "Validate authorizations explicitly on every request.", "CWE-284"),
    ("CWE-310", "Cryptographic Issues", "Weaknesses in this category are related to the design and implementation of cryptographic operations.", "Medium", "Adhere to NIST cryptographic guidelines.", "CWE-693"),
    ("CWE-345", "Insufficient Verification of Data Authenticity", "The software does not sufficiently verify the origin or authenticity of data.", "Medium", "Use HMAC / digital signatures for critical payloads.", "CWE-693"),
    ("CWE-703", "Improper Check or Handling of Exceptional Conditions", "Weaknesses in this category are related to the failure to properly catch or handle exceptions.", "Low", "Handle all exceptions gracefully without leaking stack traces.", "CWE-693"),
    ("CWE-693", "Protection Mechanism Failure", "The product does not properly implement an architectural protection mechanism.", "High", "Validate security controls with defensive layers.", "CWE-693"),
    ("CWE-1188", "Insecure Default Initialization of Resource", "The software initializes a resource with insecure default values.", "Medium", "Ensure secure-by-default configuration profiles.", "CWE-693"),
    ("CWE-1321", "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')", "The software receives an object from an untrusted source, and copies properties into a prototype object without validating keys such as '__proto__'.", "High", "Freeze Object.prototype; validate recursive property merge keys.", "CWE-20")
]


def ingest_cwes(conn: sqlite3.Connection) -> int:
    timestamp = datetime.now(timezone.utc).isoformat()
    cursor = conn.cursor()
    count = 0
    for cwe_id, name, desc, likelihood, mitigations, parent in CORE_CWES:
        source_url = f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html"
        cursor.execute(
            """
            INSERT INTO cwe (cwe_id, name, description, extended_description, likelihood, mitigations, parent_cwe, source_url, source_name, ingested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cwe_id) DO UPDATE SET
                name=excluded.name,
                description=excluded.description,
                likelihood=excluded.likelihood,
                mitigations=excluded.mitigations,
                parent_cwe=excluded.parent_cwe,
                ingested_at=excluded.ingested_at
            """,
            (cwe_id, name, desc, "", likelihood, mitigations, parent, source_url, "MITRE CWE", timestamp),
        )
        count += 1
    conn.commit()
    return count
