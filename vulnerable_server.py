#!/usr/bin/env python3
import base64
import json
import os
import time
from http.server import ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from xml.etree import ElementTree

import server


HOST = os.environ.get("SOAP_DAST_HOST", "127.0.0.1")
PORT = int(os.environ.get("SOAP_DAST_VULN_PORT", "8089"))
PUBLIC_HOST = os.environ.get("SOAP_DAST_PUBLIC_HOST", HOST)
PUBLIC_PORT = int(os.environ.get("SOAP_DAST_VULN_PUBLIC_PORT", str(PORT)))


def b64url_decode(value):
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def insecure_verify_jwt(token):
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None, "malformed_token"

        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))

        # Vulnerability: accepts unsigned JWTs and does not validate signatures.
        if header.get("alg") == "none":
            return payload, None

        # Vulnerability: for signed-looking tokens, only parses claims and ignores
        # HMAC validation, issuer validation, nbf validation, and server-side session binding.
        exp = int(payload.get("exp", int(time.time()) + 3600))
        if int(time.time()) >= exp:
            return None, "token_expired"
        return payload, None
    except Exception:
        return None, "malformed_token"


def unsafe_response_element(action, fields):
    lines = [f"    <lab:{action}Response>"]
    for key, value in fields.items():
        # Vulnerability: intentionally does not XML-escape reflected values.
        lines.append(f"      <lab:{key}>{value}</lab:{key}>")
    lines.append(f"    </lab:{action}Response>")
    return server.soap_envelope("\n".join(lines))


VULNERABLE_WSDL = server.WSDL.replace(
    f":{server.PUBLIC_PORT}/", f":{PUBLIC_PORT}/"
).replace(
    f"://{server.PUBLIC_HOST}:", f"://{PUBLIC_HOST}:"
).replace(
    "SecurityTestService", "VulnerableSecurityTestService"
)


class VulnerableSoapDastHandler(server.SoapDastHandler):
    server_version = "VulnerableSoapDastLab/1.0"

    def do_TRACE(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        reflected = [f"{self.command} {self.path} {self.request_version}"]
        reflected.extend(f"{key}: {value}" for key, value in self.headers.items())
        reflected.append("")
        reflected.append(body)
        # Vulnerability: TRACE reflects request metadata/body.
        self.send_body(200, "\n".join(reflected), "message/http")

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.send_json(
                200,
                {
                    "name": "Vulnerable SOAP DAST Lab",
                    "soap": "/soap",
                    "wsdl": "/soap?wsdl",
                    "verbs": "/verbs",
                    "audit": "/audit",
                    "vulnerabilities": [
                        "jwt_alg_none",
                        "jwt_signature_bypass",
                        "idor",
                        "session_fixation",
                        "refresh_token_reuse",
                        "trace_reflection",
                        "unsafe_xml_reflection",
                    ],
                },
            )
            return
        if parsed.path == "/soap" and "wsdl" in parse_qs(parsed.query, keep_blank_values=True):
            self.send_body(200, VULNERABLE_WSDL)
            return
        super().do_GET()

    def do_POST(self):
        if urlparse(self.path).path != "/soap":
            self.send_json(404, {"error": "not_found"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
        if "<!DOCTYPE" in raw_body.upper() or "<!ENTITY" in raw_body.upper():
            # Vulnerability signal: this deliberately acknowledges dangerous XML features
            # instead of rejecting them before parsing.
            self.send_body(
                200,
                unsafe_response_element(
                    "XmlEntityProbe",
                    {
                        "Status": "doctype_seen",
                        "Note": "Vulnerable mode accepted a payload containing DOCTYPE/ENTITY markers.",
                        "Echo": raw_body[:500],
                    },
                ),
            )
            return

        try:
            root = ElementTree.fromstring(raw_body)
        except ElementTree.ParseError as exc:
            # Vulnerability: returns parser detail and reflected body fragment.
            self.send_body(
                400,
                unsafe_response_element(
                    "MalformedXml",
                    {"ParserError": str(exc), "BodyEcho": raw_body[:500]},
                ),
            )
            return

        action = self.headers.get("SOAPAction", "").strip('"') or self.detect_action(root)
        handlers = {
            "Login": self.soap_login,
            "RefreshToken": self.soap_refresh_token,
            "ValidateToken": self.soap_validate_token,
            "GetAccount": self.soap_get_account,
            "TransferFunds": self.soap_transfer_funds,
            "SearchUser": self.soap_search_user,
            "Logout": self.soap_logout,
        }
        handler = handlers.get(action)
        if not handler:
            self.send_body(
                400,
                unsafe_response_element(
                    "UnknownAction",
                    {"Action": action, "Hint": "SOAPAction is reflected without XML escaping."},
                ),
            )
            return
        handler(root)

    def require_auth(self):
        token = self.bearer_token() or self.headers.get("X-Session-Token", "")
        if not token:
            return None, "missing_bearer_token"
        payload, error = insecure_verify_jwt(token)
        if error:
            return None, error
        # Vulnerability: cookie/session binding is not enforced.
        return payload, None

    def soap_login(self, root):
        username = server.xml_text(root, "Username")
        password = server.xml_text(root, "Password")
        user = server.USERS.get(username)
        if not user or user["password"] != password:
            self.send_body(401, server.soap_fault("Auth.InvalidCredentials", "Invalid username or password"))
            return

        access_token, refresh_token, session_id, claims = server.issue_tokens(username)
        fixed_session = self.headers.get("X-Fixed-Session-Id")
        if fixed_session:
            # Vulnerability: session fixation through attacker-supplied session id.
            server.SESSIONS[fixed_session] = server.SESSIONS.pop(session_id)
            refresh_record = server.REFRESH_TOKENS[refresh_token]
            refresh_record["session_id"] = fixed_session
            access_token, claims = server.make_jwt(username, user["role"], fixed_session)
            session_id = fixed_session

        headers = {
            # Vulnerability: intentionally omits HttpOnly/SameSite attributes.
            "Set-Cookie": f"DASTSESSION={session_id}; Path=/"
        }
        self.send_body(
            200,
            unsafe_response_element(
                "Login",
                {
                    "AccessToken": access_token,
                    "RefreshToken": refresh_token,
                    "SessionId": session_id,
                    "ExpiresAt": claims["exp"],
                    "TokenId": claims["jti"],
                    "VulnerableMode": "true",
                },
            ),
            headers=headers,
        )

    def soap_refresh_token(self, root):
        refresh_token = server.xml_text(root, "RefreshToken")
        record = server.REFRESH_TOKENS.get(refresh_token)
        if not record:
            self.send_body(401, server.soap_fault("Auth.RefreshFailed", "refresh_token_not_found"))
            return

        # Vulnerability: refresh token is reusable and not rotated.
        user = server.USERS[record["username"]]
        access_token, claims = server.make_jwt(record["username"], user["role"], record["session_id"])
        self.send_body(
            200,
            unsafe_response_element(
                "RefreshToken",
                {
                    "AccessToken": access_token,
                    "RefreshToken": refresh_token,
                    "SessionId": record["session_id"],
                    "ExpiresAt": claims["exp"],
                    "TokenId": claims["jti"],
                    "Rotated": "false",
                    "Vulnerability": "refresh token reuse allowed",
                },
            ),
        )

    def soap_validate_token(self, root):
        payload, error = self.require_auth()
        if error:
            self.send_body(401, server.soap_fault("Auth.TokenInvalid", error))
            return
        self.send_body(
            200,
            unsafe_response_element(
                "ValidateToken",
                {
                    "Subject": payload.get("sub", ""),
                    "Role": payload.get("role", ""),
                    "SessionId": payload.get("sid", ""),
                    "TokenId": payload.get("jti", ""),
                    "ExpiresAt": payload.get("exp", ""),
                    "Vulnerability": "signature and session binding may be bypassed",
                },
            ),
        )

    def soap_get_account(self, root):
        payload, error = self.require_auth()
        if error:
            self.send_body(401, server.soap_fault("Auth.Required", error))
            return
        requested_account = server.xml_text(root, "AccountId") or "1001"
        owner = next(
            (name for name, user in server.USERS.items() if user["account_id"] == requested_account),
            payload.get("sub", "unknown"),
        )
        balance = server.USERS.get(owner, {}).get("balance", "unknown")
        # Vulnerability: IDOR. Any authenticated caller can request any account id.
        self.send_body(
            200,
            unsafe_response_element(
                "GetAccount",
                {
                    "AccountId": requested_account,
                    "Owner": owner,
                    "Balance": balance,
                    "RequestedBy": payload.get("sub", ""),
                    "Vulnerability": "idor_account_access",
                },
            ),
        )

    def soap_search_user(self, root):
        payload, error = self.require_auth()
        if error:
            self.send_body(401, server.soap_fault("Auth.Required", error))
            return
        query = server.xml_text(root, "Query")
        matches = [name for name in server.USERS if query.lower() in name.lower()]
        self.send_body(
            200,
            unsafe_response_element(
                "SearchUser",
                {
                    "Query": query,
                    "Matches": ",".join(matches),
                    "FuzzEcho": query,
                    "Vulnerability": "unsafe_reflection_without_xml_escape",
                },
            ),
        )


def main():
    httpd = ThreadingHTTPServer((HOST, PORT), VulnerableSoapDastHandler)
    print(f"Vulnerable SOAP DAST Lab running at http://{HOST}:{PORT}")
    print(f"WSDL available at http://{HOST}:{PORT}/soap?wsdl")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
