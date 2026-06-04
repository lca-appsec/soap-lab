#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from xml.etree import ElementTree


HOST = os.environ.get("SOAP_DAST_HOST", "127.0.0.1")
PORT = int(os.environ.get("SOAP_DAST_PORT", "8088"))
PUBLIC_HOST = os.environ.get("SOAP_DAST_PUBLIC_HOST", HOST)
PUBLIC_PORT = int(os.environ.get("SOAP_DAST_PUBLIC_PORT", str(PORT)))
JWT_SECRET = "change-me-only-for-this-dast-lab"
JWT_ISSUER = "soap-dast-lab"
ACCESS_TOKEN_TTL_SECONDS = 180
REFRESH_TOKEN_TTL_SECONDS = 900
SESSION_TTL_SECONDS = 600

USERS = {
    "admin_aurora": {
        "password": "R9v!tQ2mZx#4",
        "role": "admin",
        "account_id": "9001",
        "balance": 99250.00,
    },
    "admin_boreal": {
        "password": "K7p@Lw3sDn$8",
        "role": "admin",
        "account_id": "9002",
        "balance": 87410.20,
    },
    "admin_cosmos": {
        "password": "M4x#Qr8nVp!1",
        "role": "admin",
        "account_id": "9003",
        "balance": 76500.75,
    },
    "admin_delta": {
        "password": "H2s$Yu6cJk@9",
        "role": "admin",
        "account_id": "9004",
        "balance": 68220.40,
    },
    "admin_equinox": {
        "password": "T5n!Ba9wLf#3",
        "role": "admin",
        "account_id": "9005",
        "balance": 59100.10,
    },
    "user_apollo": {
        "password": "P6d@Xe1mRt$7",
        "role": "user",
        "account_id": "1001",
        "balance": 1280.50,
    },
    "user_bianca": {
        "password": "W8k#No2vHs!5",
        "role": "user",
        "account_id": "1002",
        "balance": 940.25,
    },
    "user_cairo": {
        "password": "C3y$Pa7qZm@2",
        "role": "user",
        "account_id": "1003",
        "balance": 2100.00,
    },
    "user_diana": {
        "password": "L1f!Gw5rKb#6",
        "role": "user",
        "account_id": "1004",
        "balance": 315.90,
    },
    "user_elias": {
        "password": "V9m@Sd4xQh$1",
        "role": "user",
        "account_id": "1005",
        "balance": 1785.35,
    },
}

PRODUCTS = {
    "SKU-100": {"name": "Notebook Orion 14", "price": 4299.90, "stock": 18},
    "SKU-200": {"name": "Monitor Nebula 27", "price": 1899.00, "stock": 34},
    "SKU-300": {"name": "Teclado Atlas Pro", "price": 349.90, "stock": 120},
    "SKU-400": {"name": "Mouse Pulse Wireless", "price": 229.50, "stock": 87},
    "SKU-500": {"name": "Dock Station Vega", "price": 799.00, "stock": 22},
}

REFRESH_TOKENS = {}
SESSIONS = {}
AUDIT_LOG = []


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(value):
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def now():
    return int(time.time())


def token_fingerprint(token):
    if not token:
        return ""
    return hashlib.sha256(token.encode()).hexdigest()[:16]


def make_jwt(username, role, session_id):
    issued_at = now()
    header = {"typ": "JWT", "alg": "HS256"}
    payload = {
        "iss": JWT_ISSUER,
        "sub": username,
        "role": role,
        "sid": session_id,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": issued_at + ACCESS_TOKEN_TTL_SECONDS,
        "jti": str(uuid.uuid4()),
    }
    header_part = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_part = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_part}.{payload_part}".encode()
    signature = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return f"{header_part}.{payload_part}.{b64url_encode(signature)}", payload


def verify_jwt(token):
    try:
        header_part, payload_part, signature_part = token.split(".")
        signing_input = f"{header_part}.{payload_part}".encode()
        expected = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
        supplied = b64url_decode(signature_part)
        if not hmac.compare_digest(expected, supplied):
            return None, "invalid_signature"
        payload = json.loads(b64url_decode(payload_part))
        current = now()
        if payload.get("iss") != JWT_ISSUER:
            return None, "invalid_issuer"
        if current < int(payload.get("nbf", 0)):
            return None, "token_not_yet_valid"
        if current >= int(payload.get("exp", 0)):
            return None, "token_expired"
        session = SESSIONS.get(payload.get("sid"))
        if not session or session["username"] != payload.get("sub"):
            return None, "session_not_found"
        if current >= session["expires_at"]:
            return None, "session_expired"
        return payload, None
    except Exception:
        return None, "malformed_token"


def xml_text(root, name):
    fallback = ""
    for element in root.iter():
        if element.tag.split("}")[-1] == name:
            value = element.text or ""
            if value.strip():
                return value
            fallback = value
    return fallback


def soap_envelope(body_xml):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:lab="urn:soap-dast-lab">
  <soap:Body>
{body_xml}
  </soap:Body>
</soap:Envelope>
"""


def soap_fault(code, message):
    return soap_envelope(f"""    <soap:Fault>
      <faultcode>{code}</faultcode>
      <faultstring>{message}</faultstring>
    </soap:Fault>""")


def response_element(action, fields):
    lines = [f"    <lab:{action}Response>"]
    for key, value in fields.items():
        lines.append(f"      <lab:{key}>{escape_xml(str(value))}</lab:{key}>")
    lines.append(f"    </lab:{action}Response>")
    return soap_envelope("\n".join(lines))


def safe_xml_tag(value):
    tag = "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in str(value))
    if not tag or tag[0].isdigit():
        tag = f"item_{tag}"
    return tag


def value_to_xml(name, value, indent=0):
    space = " " * indent
    tag = safe_xml_tag(name)
    if isinstance(value, dict):
        lines = [f"{space}<{tag}>"]
        for child_key, child_value in value.items():
            lines.append(value_to_xml(child_key, child_value, indent + 2))
        lines.append(f"{space}</{tag}>")
        return "\n".join(lines)
    if isinstance(value, list):
        lines = [f"{space}<{tag}>"]
        item_name = tag[:-1] if tag.endswith("s") and len(tag) > 1 else "item"
        for item in value:
            lines.append(value_to_xml(item_name, item, indent + 2))
        lines.append(f"{space}</{tag}>")
        return "\n".join(lines)
    if value is None:
        value = ""
    return f"{space}<{tag}>{escape_xml(str(value))}</{tag}>"


def xml_document(root_name, data):
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + value_to_xml(root_name, data) + "\n"


def escape_xml(value):
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def issue_tokens(username):
    session_id = secrets.token_urlsafe(24)
    refresh_token = secrets.token_urlsafe(40)
    user = USERS[username]
    SESSIONS[session_id] = {
        "username": username,
        "created_at": now(),
        "expires_at": now() + SESSION_TTL_SECONDS,
    }
    REFRESH_TOKENS[refresh_token] = {
        "username": username,
        "session_id": session_id,
        "expires_at": now() + REFRESH_TOKEN_TTL_SECONDS,
        "active": True,
    }
    access_token, claims = make_jwt(username, user["role"], session_id)
    return access_token, refresh_token, session_id, claims


def rotate_refresh_token(refresh_token):
    record = REFRESH_TOKENS.get(refresh_token)
    if not record:
        return None, "refresh_token_not_found"
    if not record["active"]:
        return None, "refresh_token_reused"
    if now() >= record["expires_at"]:
        return None, "refresh_token_expired"
    session = SESSIONS.get(record["session_id"])
    if not session or now() >= session["expires_at"]:
        return None, "session_expired"

    record["active"] = False
    new_refresh_token = secrets.token_urlsafe(40)
    REFRESH_TOKENS[new_refresh_token] = {
        "username": record["username"],
        "session_id": record["session_id"],
        "expires_at": now() + REFRESH_TOKEN_TTL_SECONDS,
        "active": True,
    }
    session["expires_at"] = now() + SESSION_TTL_SECONDS
    user = USERS[record["username"]]
    access_token, claims = make_jwt(record["username"], user["role"], record["session_id"])
    return (access_token, new_refresh_token, record["session_id"], claims), None


WSDL = f"""<?xml version="1.0" encoding="UTF-8"?>
<definitions name="SoapDastLab"
  targetNamespace="urn:soap-dast-lab"
  xmlns="http://schemas.xmlsoap.org/wsdl/"
  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
  xmlns:tns="urn:soap-dast-lab">
  <service name="SecurityTestService">
    <documentation>SOAP API target for authorized DAST testing. Endpoint: http://{PUBLIC_HOST}:{PUBLIC_PORT}/soap</documentation>
    <port name="SecurityTestPort" binding="tns:SecurityTestBinding">
      <soap:address location="http://{PUBLIC_HOST}:{PUBLIC_PORT}/soap"/>
    </port>
  </service>
  <binding name="SecurityTestBinding" type="tns:SecurityTestPortType">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="Login"><soap:operation soapAction="Login"/></operation>
    <operation name="RefreshToken"><soap:operation soapAction="RefreshToken"/></operation>
    <operation name="ValidateToken"><soap:operation soapAction="ValidateToken"/></operation>
    <operation name="GetAccount"><soap:operation soapAction="GetAccount"/></operation>
    <operation name="TransferFunds"><soap:operation soapAction="TransferFunds"/></operation>
    <operation name="SearchUser"><soap:operation soapAction="SearchUser"/></operation>
    <operation name="Logout"><soap:operation soapAction="Logout"/></operation>
  </binding>
  <portType name="SecurityTestPortType"/>
</definitions>
"""


class SoapDastHandler(BaseHTTPRequestHandler):
    server_version = "SoapDastLab/1.0"

    def log_message(self, fmt, *args):
        AUDIT_LOG.append(
            {
                "type": "http",
                "time": now(),
                "client": self.client_address[0],
                "method": self.command,
                "path": self.path,
                "message": fmt % args,
            }
        )
        super().log_message(fmt, *args)

    def log_auth_event(
        self,
        event,
        status,
        username=None,
        role=None,
        session_id=None,
        token_id=None,
        error=None,
        details=None,
    ):
        entry = {
            "type": "auth",
            "time": now(),
            "client": self.client_address[0],
            "method": self.command,
            "path": self.path,
            "event": event,
            "status": status,
        }
        optional = {
            "username": username,
            "role": role,
            "session_id": session_id,
            "token_id": token_id,
            "error": error,
            "details": details,
        }
        for key, value in optional.items():
            if value not in (None, "", {}):
                entry[key] = value
        AUDIT_LOG.append(entry)

    def send_body(self, status, body, content_type="application/xml", headers=None):
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-DAST-Lab", "soap-jwt-refresh-session")
        self.send_header("Cache-Control", "no-store")
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def send_json(self, status, data, headers=None):
        self.send_body(status, xml_document("response", data), "application/xml", headers)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, POST, PUSH, PUT, PATCH, DELETE, OPTIONS, TRACE")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUSH, PUT, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, SOAPAction, X-Session-Token")
        self.send_header("X-DAST-Lab", "verb-discovery")
        self.end_headers()

    def do_TRACE(self):
        self.send_body(405, "TRACE is intentionally rejected by the lab target.\n", "text/plain")

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.send_json(
                200,
                {
                    "name": "SOAP DAST Lab",
                    "soap": "/soap",
                    "wsdl": "/soap?wsdl",
                    "verbs": "/verbs",
                    "admin": "/admin",
                    "admin_products": "/admin/products",
                    "user": "/user",
                    "user_products": "/user/products",
                    "audit": "/audit",
                },
            )
            return
        if parsed.path == "/soap" and "wsdl" in parse_qs(parsed.query, keep_blank_values=True):
            self.send_body(200, WSDL)
            return
        if parsed.path == "/soap":
            self.send_json(
                200,
                {
                    "service": "SOAP DAST Lab",
                    "wsdl": "/soap?wsdl",
                    "soap_endpoint": "/soap",
                    "required_method": "POST",
                    "required_headers": ["Content-Type: text/xml", "SOAPAction: <operation>"],
                    "operations": [
                        "Login",
                        "RefreshToken",
                        "ValidateToken",
                        "GetAccount",
                        "TransferFunds",
                        "SearchUser",
                        "Logout",
                    ],
                },
            )
            return
        if parsed.path == "/audit":
            self.send_json(200, {"events": AUDIT_LOG[-50:]})
            return
        if parsed.path == "/verbs":
            self.send_json(200, self.verb_payload("GET"))
            return
        if parsed.path in {"/admin", "/admin/products"}:
            self.handle_admin_get()
            return
        if parsed.path in {"/user", "/user/products"}:
            self.handle_user_get()
            return
        self.send_json(404, {"error": "not_found"})

    def do_PUT(self):
        if urlparse(self.path).path == "/admin/products":
            self.handle_product_edit()
            return
        if urlparse(self.path).path == "/user/products":
            self.handle_user_write_forbidden("PUT")
            return
        self.handle_verb_probe("PUT")

    def do_PATCH(self):
        if urlparse(self.path).path == "/admin/products":
            self.handle_product_edit()
            return
        if urlparse(self.path).path == "/user/products":
            self.handle_user_write_forbidden("PATCH")
            return
        self.handle_verb_probe("PATCH")

    def do_PUSH(self):
        parsed = urlparse(self.path)
        if parsed.path == "/admin/products":
            self.handle_product_edit()
            return
        if parsed.path == "/user/products":
            self.handle_user_write_forbidden("PUSH")
            return
        self.send_json(404, {"error": "not_found"})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path == "/admin/products":
            self.handle_product_delete(parsed)
            return
        if parsed.path == "/user/products":
            self.handle_user_write_forbidden("DELETE")
            return
        self.handle_verb_probe("DELETE")

    def handle_verb_probe(self, method):
        if urlparse(self.path).path != "/verbs":
            self.send_json(404, {"error": "not_found"})
            return
        payload, error = self.require_auth()
        status = 200 if payload else 401
        self.send_json(status, self.verb_payload(method, payload, error))

    def require_role(self, expected_role):
        payload, error = self.require_auth()
        if error:
            return None, error
        if payload.get("role") != expected_role:
            return None, "forbidden_role"
        return payload, None

    def products_for_admin(self):
        return [
            {
                "sku": sku,
                "name": product["name"],
                "price": product["price"],
                "stock": product["stock"],
            }
            for sku, product in PRODUCTS.items()
        ]

    def products_for_user(self):
        return [
            {
                "sku": sku,
                "name": product["name"],
                "available": product["stock"] > 0,
            }
            for sku, product in PRODUCTS.items()
        ]

    def handle_admin_get(self):
        payload, error = self.require_role("admin")
        if error:
            status = 401 if error != "forbidden_role" else 403
            self.send_json(status, {"error": error, "required_role": "admin"})
            return
        self.send_json(
            200,
            {
                "path": "/admin",
                "authenticated_as": payload["sub"],
                "role": payload["role"],
                "capabilities": ["GET list", "POST create", "PUSH edit", "DELETE delete"],
                "products": self.products_for_admin(),
            },
        )

    def handle_user_get(self):
        payload, error = self.require_role("user")
        if error:
            status = 401 if error != "forbidden_role" else 403
            self.send_json(status, {"error": error, "required_role": "user"})
            return
        self.send_json(
            200,
            {
                "path": "/user",
                "authenticated_as": payload["sub"],
                "role": payload["role"],
                "catalog": self.products_for_user(),
                "message": "User role can only use GET. Prices and write operations are hidden.",
            },
        )

    def read_structured_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
        content_type = self.headers.get("Content-Type", "")
        if "json" in content_type:
            return json.loads(raw_body or "{}")
        if not raw_body.strip():
            return {}
        root = ElementTree.fromstring(raw_body)
        return {
            child.tag.split("}")[-1]: (child.text or "")
            for child in root.iter()
            if child is not root and len(list(child)) == 0
        }

    def handle_user_write_forbidden(self, method):
        payload, error = self.require_auth()
        if error:
            self.send_json(401, {"error": error})
            return
        if payload.get("role") == "admin":
            self.send_json(
                403,
                {
                    "error": "wrong_path",
                    "message": f"Admins can use {method} on /admin/products.",
                    "allowed_path": "/admin/products",
                },
            )
            return
        self.send_json(
            403,
            {
                "error": "forbidden_method",
                "role": payload.get("role"),
                "method": method,
                "allowed_methods": ["GET"],
            },
        )

    def handle_product_create(self):
        payload, error = self.require_role("admin")
        if error:
            status = 401 if error != "forbidden_role" else 403
            self.send_json(status, {"error": error, "required_role": "admin"})
            return

        try:
            data = self.read_structured_body()
            sku = str(data.get("sku", "")).strip()
            name = str(data.get("name", "")).strip()
            price = float(data.get("price"))
            stock = int(data.get("stock", 0))
        except (TypeError, ValueError, json.JSONDecodeError, ElementTree.ParseError):
            self.send_json(
                400,
                {
                    "error": "invalid_xml",
                    "expected": {"sku": "SKU-600", "name": "Produto Demo", "price": 199.90, "stock": 10},
                },
            )
            return

        if not sku or not name:
            self.send_json(400, {"error": "missing_required_fields", "required": ["sku", "name", "price"]})
            return
        if sku in PRODUCTS:
            self.send_json(409, {"error": "product_already_exists", "sku": sku})
            return
        if price <= 0 or stock < 0:
            self.send_json(400, {"error": "invalid_product_values"})
            return

        PRODUCTS[sku] = {"name": name, "price": round(price, 2), "stock": stock}
        self.send_json(
            201,
            {
                "path": "/admin/products",
                "method": "POST",
                "created_by": payload["sub"],
                "product": {"sku": sku, **PRODUCTS[sku]},
            },
        )

    def handle_product_edit(self):
        payload, error = self.require_role("admin")
        if error:
            status = 401 if error != "forbidden_role" else 403
            self.send_json(status, {"error": error, "required_role": "admin"})
            return

        try:
            data = self.read_structured_body()
            sku = str(data.get("sku", ""))
        except (json.JSONDecodeError, ElementTree.ParseError):
            self.send_json(400, {"error": "invalid_xml", "expected": {"sku": "SKU-100", "price": 4299.90}})
            return

        if sku not in PRODUCTS:
            self.send_json(404, {"error": "product_not_found", "sku": sku})
            return

        before = {"sku": sku, **PRODUCTS[sku]}
        if "name" in data:
            name = str(data["name"]).strip()
            if not name:
                self.send_json(400, {"error": "invalid_name"})
                return
            PRODUCTS[sku]["name"] = name
        if "price" in data:
            try:
                price = float(data["price"])
            except (TypeError, ValueError):
                self.send_json(400, {"error": "invalid_price"})
                return
            if price <= 0:
                self.send_json(400, {"error": "invalid_price", "message": "price must be positive"})
                return
            PRODUCTS[sku]["price"] = round(price, 2)
        if "stock" in data:
            try:
                stock = int(data["stock"])
            except (TypeError, ValueError):
                self.send_json(400, {"error": "invalid_stock"})
                return
            if stock < 0:
                self.send_json(400, {"error": "invalid_stock", "message": "stock must not be negative"})
                return
            PRODUCTS[sku]["stock"] = stock

        self.send_json(
            200,
            {
                "path": "/admin/products",
                "method": self.command,
                "updated_by": payload["sub"],
                "before": before,
                "after": {"sku": sku, **PRODUCTS[sku]},
            },
        )

    def handle_product_delete(self, parsed):
        payload, error = self.require_role("admin")
        if error:
            status = 401 if error != "forbidden_role" else 403
            self.send_json(status, {"error": error, "required_role": "admin"})
            return

        query = parse_qs(parsed.query, keep_blank_values=True)
        sku = query.get("sku", [""])[0]
        if not sku:
            try:
                sku = str(self.read_structured_body().get("sku", ""))
            except (json.JSONDecodeError, ElementTree.ParseError):
                self.send_json(400, {"error": "invalid_xml", "expected": {"sku": "SKU-100"}})
                return
        if sku not in PRODUCTS:
            self.send_json(404, {"error": "product_not_found", "sku": sku})
            return
        deleted = PRODUCTS.pop(sku)
        self.send_json(
            200,
            {
                "path": "/admin/products",
                "method": "DELETE",
                "deleted_by": payload["sub"],
                "deleted": {"sku": sku, **deleted},
            },
        )

    def verb_payload(self, method, payload=None, error=None):
        return {
            "method": method,
            "authenticated": payload is not None,
            "auth_error": error,
            "note": "Use this endpoint to verify DAST HTTP verb handling and auth enforcement.",
        }

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/admin/products":
            self.handle_product_create()
            return
        if parsed.path == "/user/products":
            self.handle_user_write_forbidden("POST")
            return
        if parsed.path != "/soap":
            self.send_json(404, {"error": "not_found"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
        try:
            root = ElementTree.fromstring(raw_body)
        except ElementTree.ParseError as exc:
            self.send_body(400, soap_fault("Client.MalformedXml", str(exc)))
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
            self.send_body(400, soap_fault("Client.UnknownAction", f"Unknown SOAPAction: {action}"))
            return
        handler(root)

    def detect_action(self, root):
        for element in root.iter():
            local = element.tag.split("}")[-1]
            if local in {
                "Login",
                "RefreshToken",
                "ValidateToken",
                "GetAccount",
                "TransferFunds",
                "SearchUser",
                "Logout",
            }:
                return local
        return ""

    def bearer_token(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth.removeprefix("Bearer ").strip()
        return ""

    def session_cookie(self):
        jar = cookies.SimpleCookie(self.headers.get("Cookie"))
        morsel = jar.get("DASTSESSION")
        return morsel.value if morsel else ""

    def require_auth(self):
        token = self.bearer_token() or self.headers.get("X-Session-Token", "")
        if not token:
            self.log_auth_event("access_token_missing", "failure", error="missing_bearer_token")
            return None, "missing_bearer_token"
        payload, error = verify_jwt(token)
        if error:
            self.log_auth_event(
                "access_token_validation",
                "failure",
                error=error,
                details={"access_token_fingerprint": token_fingerprint(token)},
            )
            return None, error
        cookie_session = self.session_cookie()
        if cookie_session and cookie_session != payload["sid"]:
            self.log_auth_event(
                "access_token_validation",
                "failure",
                username=payload.get("sub"),
                role=payload.get("role"),
                session_id=payload.get("sid"),
                token_id=payload.get("jti"),
                error="session_cookie_mismatch",
                details={
                    "access_token_fingerprint": token_fingerprint(token),
                    "cookie_session_id": cookie_session,
                },
            )
            return None, "session_cookie_mismatch"
        self.log_auth_event(
            "access_token_validation",
            "success",
            username=payload.get("sub"),
            role=payload.get("role"),
            session_id=payload.get("sid"),
            token_id=payload.get("jti"),
            details={"access_token_fingerprint": token_fingerprint(token)},
        )
        return payload, None

    def soap_login(self, root):
        username = xml_text(root, "Username")
        password = xml_text(root, "Password")
        user = USERS.get(username)
        if not user or not hmac.compare_digest(user["password"], password):
            self.log_auth_event("login", "failure", username=username, error="invalid_credentials")
            self.send_body(401, soap_fault("Auth.InvalidCredentials", "Invalid username or password"))
            return
        access_token, refresh_token, session_id, claims = issue_tokens(username)
        self.log_auth_event(
            "login",
            "success",
            username=username,
            role=user["role"],
            session_id=session_id,
            token_id=claims["jti"],
            details={
                "access_token_fingerprint": token_fingerprint(access_token),
                "refresh_token_fingerprint": token_fingerprint(refresh_token),
                "access_token_expires_at": claims["exp"],
                "access_token_ttl_seconds": ACCESS_TOKEN_TTL_SECONDS,
            },
        )
        headers = {"Set-Cookie": f"DASTSESSION={session_id}; HttpOnly; SameSite=Lax; Path=/"}
        self.send_body(
            200,
            response_element(
                "Login",
                {
                    "AccessToken": access_token,
                    "RefreshToken": refresh_token,
                    "SessionId": session_id,
                    "ExpiresAt": claims["exp"],
                    "TokenId": claims["jti"],
                },
            ),
            headers=headers,
        )

    def soap_refresh_token(self, root):
        refresh_token = xml_text(root, "RefreshToken")
        old_refresh_fingerprint = token_fingerprint(refresh_token)
        result, error = rotate_refresh_token(refresh_token)
        if error:
            self.log_auth_event(
                "refresh_token",
                "failure",
                error=error,
                details={"refresh_token_fingerprint": old_refresh_fingerprint},
            )
            self.send_body(401, soap_fault("Auth.RefreshFailed", error))
            return
        access_token, new_refresh_token, session_id, claims = result
        self.log_auth_event(
            "refresh_token",
            "success",
            username=claims["sub"],
            role=claims["role"],
            session_id=session_id,
            token_id=claims["jti"],
            details={
                "old_refresh_token_fingerprint": old_refresh_fingerprint,
                "new_refresh_token_fingerprint": token_fingerprint(new_refresh_token),
                "new_access_token_fingerprint": token_fingerprint(access_token),
                "access_token_expires_at": claims["exp"],
                "refresh_rotated": True,
            },
        )
        headers = {"Set-Cookie": f"DASTSESSION={session_id}; HttpOnly; SameSite=Lax; Path=/"}
        self.send_body(
            200,
            response_element(
                "RefreshToken",
                {
                    "AccessToken": access_token,
                    "RefreshToken": new_refresh_token,
                    "SessionId": session_id,
                    "ExpiresAt": claims["exp"],
                    "TokenId": claims["jti"],
                    "Rotated": "true",
                },
            ),
            headers=headers,
        )

    def soap_validate_token(self, root):
        payload, error = self.require_auth()
        if error:
            self.log_auth_event("validate_token", "failure", error=error)
            self.send_body(401, soap_fault("Auth.TokenInvalid", error))
            return
        self.log_auth_event(
            "validate_token",
            "success",
            username=payload["sub"],
            role=payload["role"],
            session_id=payload["sid"],
            token_id=payload["jti"],
        )
        self.send_body(
            200,
            response_element(
                "ValidateToken",
                {
                    "Subject": payload["sub"],
                    "Role": payload["role"],
                    "SessionId": payload["sid"],
                    "TokenId": payload["jti"],
                    "ExpiresAt": payload["exp"],
                },
            ),
        )

    def soap_get_account(self, root):
        payload, error = self.require_auth()
        if error:
            self.send_body(401, soap_fault("Auth.Required", error))
            return
        requested_account = xml_text(root, "AccountId")
        user = USERS[payload["sub"]]
        if requested_account and requested_account != user["account_id"] and payload["role"] != "admin":
            self.send_body(403, soap_fault("Auth.Forbidden", "Account does not belong to caller"))
            return
        self.send_body(
            200,
            response_element(
                "GetAccount",
                {
                    "AccountId": requested_account or user["account_id"],
                    "Owner": payload["sub"],
                    "Balance": f"{user['balance']:.2f}",
                    "Role": payload["role"],
                },
            ),
        )

    def soap_transfer_funds(self, root):
        payload, error = self.require_auth()
        if error:
            self.send_body(401, soap_fault("Auth.Required", error))
            return
        amount_raw = xml_text(root, "Amount")
        to_account = xml_text(root, "ToAccount")
        try:
            amount = float(amount_raw)
        except ValueError:
            self.send_body(400, soap_fault("Client.InvalidAmount", "Amount must be numeric"))
            return
        if amount <= 0:
            self.send_body(400, soap_fault("Client.InvalidAmount", "Amount must be positive"))
            return
        if amount > 5000 and payload["role"] != "admin":
            self.send_body(403, soap_fault("Auth.Forbidden", "Only admins can transfer more than 5000"))
            return
        self.send_body(
            200,
            response_element(
                "TransferFunds",
                {
                    "Status": "accepted",
                    "FromUser": payload["sub"],
                    "ToAccount": to_account,
                    "Amount": f"{amount:.2f}",
                    "Reference": str(uuid.uuid4()),
                },
            ),
        )

    def soap_search_user(self, root):
        payload, error = self.require_auth()
        if error:
            self.send_body(401, soap_fault("Auth.Required", error))
            return
        query = xml_text(root, "Query")
        matches = [name for name in USERS if query.lower() in name.lower()]
        self.send_body(
            200,
            response_element(
                "SearchUser",
                {
                    "Query": query,
                    "Matches": ",".join(matches),
                    "FuzzEcho": query[:250],
                },
            ),
        )

    def soap_logout(self, root):
        refresh_token = xml_text(root, "RefreshToken")
        payload, error = self.require_auth()
        if error:
            self.log_auth_event("logout", "failure", error=error)
            self.send_body(401, soap_fault("Auth.Required", error))
            return
        session = SESSIONS.pop(payload["sid"], None)
        if refresh_token in REFRESH_TOKENS:
            REFRESH_TOKENS[refresh_token]["active"] = False
        self.log_auth_event(
            "logout",
            "success",
            username=payload["sub"],
            role=payload["role"],
            session_id=payload["sid"],
            token_id=payload["jti"],
            details={
                "session_removed": session is not None,
                "refresh_token_fingerprint": token_fingerprint(refresh_token),
            },
        )
        self.send_body(
            200,
            response_element(
                "Logout",
                {
                    "Status": "logged_out",
                    "SessionRemoved": str(session is not None).lower(),
                },
            ),
            headers={"Set-Cookie": "DASTSESSION=deleted; Max-Age=0; Path=/"},
        )


def main():
    httpd = ThreadingHTTPServer((HOST, PORT), SoapDastHandler)
    print(f"SOAP DAST Lab running at http://{HOST}:{PORT}")
    print(f"WSDL available at http://{HOST}:{PORT}/soap?wsdl")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
