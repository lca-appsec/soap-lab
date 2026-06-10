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


def public_base_url():
    scheme = os.environ.get("SOAP_DAST_PUBLIC_SCHEME", "http")
    return f"{scheme}://{PUBLIC_HOST}:{PUBLIC_PORT}"


def product_for_admin(sku, product):
    return {"sku": sku, "name": product["name"], "price": product["price"], "stock": product["stock"]}


def product_for_user(sku, product):
    return {"sku": sku, "name": product["name"], "available": product["stock"] > 0}


def category_slug_from_path(path, prefix):
    if not path.startswith(prefix):
        return ""
    slug = path[len(prefix):].strip("/")
    return slug if "/" not in slug else ""


def filter_catalog_products(category, query):
    return server.catalog_products(category, query)


def looks_like_sql_injection(query):
    combined = " ".join(values[0] for values in query.values() if values).lower()
    markers = ["'", "\"", " or ", " union ", "--", ";", "/*", " drop ", " select ", " sleep(", "1=1"]
    return any(marker in combined for marker in markers)


def vulnerable_catalog_sql(category, query):
    search = query.get("q", [""])[0]
    product_id = query.get("id", [""])[0]
    sort = query.get("sort", ["name"])[0]
    promotion = query.get("promotion", [""])[0]
    min_value = query.get("min_value", [""])[0]
    sql = f"SELECT name, description, value, stock, promotion FROM products WHERE category = '{category}'"
    if product_id:
        sql += f" AND id = {product_id}"
    if search:
        sql += f" AND (name LIKE '%{search}%' OR description LIKE '%{search}%')"
    if promotion:
        sql += f" AND promotion = '{promotion}'"
    if min_value:
        sql += f" AND value >= {min_value}"
    sql += f" ORDER BY {sort}"
    return sql


def catalog_query_parameters():
    return [
        {"name": "q", "in": "query", "required": False, "schema": {"type": "string"}, "example": "camera' OR '1'='1"},
        {"name": "id", "in": "query", "required": False, "schema": {"type": "string"}, "example": "1 OR 1=1"},
        {"name": "sort", "in": "query", "required": False, "schema": {"type": "string"}, "example": "name; DROP TABLE products"},
        {"name": "promotion", "in": "query", "required": False, "schema": {"type": "string", "enum": ["yes", "no"]}},
        {"name": "min_value", "in": "query", "required": False, "schema": {"type": "string"}, "example": "0 UNION SELECT username,password,1,1,1 FROM users"},
    ]


def ecommerce_query_parameters():
    return [
        {"name": "q", "in": "query", "required": False, "schema": {"type": "string"}, "example": "orion' OR '1'='1"},
        {"name": "status", "in": "query", "required": False, "schema": {"type": "string"}, "example": "active"},
        {"name": "debug", "in": "query", "required": False, "schema": {"type": "string"}, "example": "true"},
    ]


def rest_openapi_spec():
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Vulnerable SOAP Lab - REST JSON API",
            "version": "1.0.0",
            "description": "Intentionally vulnerable REST JSON API for authorized DAST/fuzzing demonstrations.",
        },
        "servers": [{"url": public_base_url()}],
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
            },
            "schemas": {
                "LoginRequest": {
                    "type": "object",
                    "required": ["username", "password"],
                    "properties": {"username": {"type": "string"}, "password": {"type": "string"}},
                },
                "RefreshRequest": {
                    "type": "object",
                    "required": ["refreshToken"],
                    "properties": {"refreshToken": {"type": "string"}},
                },
                "Product": {
                    "type": "object",
                    "properties": {
                        "sku": {"type": "string"},
                        "name": {"type": "string"},
                        "price": {"type": "number"},
                        "stock": {"type": "integer"},
                    },
                },
            },
        },
        "paths": {
            "/api/login": {
                "post": {
                    "summary": "Login and receive JWT, refresh token, and session id",
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/LoginRequest"}}},
                    },
                    "responses": {"200": {"description": "Tokens issued"}, "401": {"description": "Invalid credentials"}},
                }
            },
            "/api/refresh": {
                "post": {
                    "summary": "Issue a new dynamic JWT using a reusable vulnerable refresh token",
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/RefreshRequest"}}},
                    },
                    "responses": {"200": {"description": "New JWT issued"}, "401": {"description": "Refresh failed"}},
                }
            },
            "/api/validate": {
                "get": {
                    "summary": "Validate bearer token using intentionally weak JWT validation",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "Token accepted"}, "401": {"description": "Token rejected"}},
                }
            },
            "/api/admin/products": {
                "get": {
                    "summary": "Admin list products with prices",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "Product list"}, "403": {"description": "Role forbidden"}},
                },
                "post": {
                    "summary": "Admin create product",
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Product"}}},
                    },
                    "responses": {"201": {"description": "Product created"}},
                },
                "delete": {
                    "summary": "Admin delete product by sku query parameter",
                    "security": [{"bearerAuth": []}],
                    "parameters": [{"name": "sku", "in": "query", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "Product deleted"}},
                },
            },
            "/api/admin/products/push": {
                "post": {
                    "summary": "Swagger-friendly alias for custom HTTP PUSH edit",
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Product"}}},
                    },
                    "responses": {"200": {"description": "Product edited"}},
                }
            },
            "/api/user/products": {
                "get": {
                    "summary": "User list products without prices",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "Catalog list"}},
                },
                "post": {
                    "summary": "User write attempt, expected to return 403",
                    "security": [{"bearerAuth": []}],
                    "responses": {"403": {"description": "Users can only GET"}},
                },
            },
            "/api/products/eletronico": {"get": {"summary": "Fuzzable electronics catalog with SQL injection parameters", "parameters": catalog_query_parameters(), "responses": {"200": {"description": "Electronics product list"}}}},
            "/api/products/smarphone": {"get": {"summary": "Fuzzable smarphone catalog with SQL injection parameters", "parameters": catalog_query_parameters(), "responses": {"200": {"description": "Smarphone product list"}}}},
            "/api/products/laptops": {"get": {"summary": "Fuzzable laptop catalog with SQL injection parameters", "parameters": catalog_query_parameters(), "responses": {"200": {"description": "Laptop product list"}}}},
            "/api/products/books": {"get": {"summary": "Fuzzable books catalog with SQL injection parameters", "parameters": catalog_query_parameters(), "responses": {"200": {"description": "Books product list"}}}},
            "/api/ecommerce/categories": {"get": {"summary": "E-commerce electronics categories stored in SQLite", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "Category list"}}}},
            "/api/ecommerce/brands": {"get": {"summary": "E-commerce electronics brands stored in SQLite", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "Brand list"}}}},
            "/api/ecommerce/deals": {"get": {"summary": "E-commerce deals and bundles", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "Deals list"}}}},
            "/api/ecommerce/cart": {"get": {"summary": "E-commerce cart records", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "Cart records"}}}},
            "/api/ecommerce/orders": {"get": {"summary": "E-commerce order records", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "Order records"}}}},
            "/api/ecommerce/reviews": {"get": {"summary": "E-commerce product reviews", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "Review records"}}}},
            "/api/ecommerce/warranty": {"get": {"summary": "E-commerce warranty plans", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "Warranty records"}}}},
            "/api/ecommerce/shipping": {"get": {"summary": "E-commerce shipping options", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "Shipping records"}}}},
            "/api/ecommerce/stores": {"get": {"summary": "E-commerce store pickup locations", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "Store records"}}}},
            "/api/ecommerce/support": {"get": {"summary": "E-commerce support tickets", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "Support records"}}}},
            "/comments": {
                "get": {"summary": "Stored XSS comment form", "responses": {"200": {"description": "HTML comment form"}}},
                "post": {
                    "summary": "Submit vulnerable comment",
                    "requestBody": {"required": True, "content": {"application/x-www-form-urlencoded": {"schema": {"type": "object", "properties": {"name": {"type": "string"}, "comment": {"type": "string"}}}}}},
                    "responses": {"200": {"description": "HTML page reflecting stored comment without escaping"}},
                },
            },
            "/api/audit": {"get": {"summary": "Read HTTP/auth audit events", "responses": {"200": {"description": "Audit log"}}}},
            "/api/login-tracking": {"get": {"summary": "Read authentication tracking evidence", "responses": {"200": {"description": "Login and token tracking evidence"}}}},
        },
    }


def xml_openapi_spec():
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Vulnerable SOAP Lab - XML/SOAP API",
            "version": "1.0.0",
            "description": "Swagger-style documentation for the XML/SOAP attack lab. SOAPAction selects the operation.",
        },
        "servers": [{"url": public_base_url()}],
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
            }
        },
        "paths": {
            "/soap?wsdl": {"get": {"summary": "Download WSDL", "responses": {"200": {"description": "WSDL XML"}}}},
            "/soap": {
                "post": {
                    "summary": "SOAP endpoint for protected business operations: GetAccount, TransferFunds, SearchUser, Logout",
                    "description": "Do not use this endpoint for authentication. Use POST /soap/auth with SOAPAction Login or ValidateToken. Use POST /soap/refreshtoken with SOAPAction RefreshToken.",
                    "parameters": [
                        {
                            "name": "SOAPAction",
                            "in": "header",
                            "required": True,
                            "schema": {
                                "type": "string",
                                "enum": [
                                    "GetAccount",
                                    "TransferFunds",
                                    "SearchUser",
                                    "Logout",
                                ],
                            },
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "text/xml": {
                                "schema": {"type": "string"},
                                "example": "<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:lab=\"urn:soap-dast-lab\"><soap:Body><lab:GetAccount><lab:AccountId>9001</lab:AccountId></lab:GetAccount></soap:Body></soap:Envelope>",
                            },
                            "application/xml": {"schema": {"type": "string"}},
                        },
                    },
                    "responses": {"200": {"description": "SOAP XML response"}, "401": {"description": "SOAP auth fault"}},
                }
            },
            "/soap/auth": {
                "post": {
                    "summary": "Dedicated SOAP authentication endpoint for Login and ValidateToken",
                    "description": "Use this endpoint with SOAPAction Login to obtain AccessToken/RefreshToken and SOAPAction ValidateToken to validate the current access token. Use /soap/refreshtoken for refresh token reauthentication. All auth interactions are written to the audit log.",
                    "parameters": [
                        {
                            "name": "SOAPAction",
                            "in": "header",
                            "required": True,
                            "schema": {"type": "string", "enum": ["Login", "ValidateToken"]},
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "text/xml": {
                                "schema": {"type": "string"},
                                "example": "<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:lab=\"urn:soap-dast-lab\"><soap:Body><lab:Login><lab:Username>admin_aurora</lab:Username><lab:Password>adminpass1</lab:Password></lab:Login></soap:Body></soap:Envelope>",
                            },
                            "application/xml": {"schema": {"type": "string"}},
                        },
                    },
                    "responses": {"200": {"description": "SOAP auth XML response"}, "400": {"description": "Unsupported auth action"}, "401": {"description": "SOAP auth fault"}},
                }
            },
            "/soap/refreshtoken": {
                "post": {
                    "summary": "Dedicated SOAP refresh token endpoint",
                    "description": "Use this endpoint with SOAPAction RefreshToken to exchange a refresh token for a new dynamic access token. Refresh token interactions are written to the audit log and /login-tracking.",
                    "parameters": [
                        {
                            "name": "SOAPAction",
                            "in": "header",
                            "required": True,
                            "schema": {"type": "string", "enum": ["RefreshToken"]},
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "text/xml": {
                                "schema": {"type": "string"},
                                "example": "<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:lab=\"urn:soap-dast-lab\"><soap:Body><lab:RefreshToken><lab:RefreshToken>YOUR_REFRESH_TOKEN</lab:RefreshToken></lab:RefreshToken></soap:Body></soap:Envelope>",
                            },
                            "application/xml": {"schema": {"type": "string"}},
                        },
                    },
                    "responses": {"200": {"description": "SOAP refresh XML response"}, "400": {"description": "Unsupported refresh action"}, "401": {"description": "SOAP auth fault"}},
                }
            },
            "/admin/products": {
                "get": {"summary": "XML admin product list", "security": [{"bearerAuth": []}], "responses": {"200": {"description": "XML response"}}},
                "post": {"summary": "XML admin create product", "security": [{"bearerAuth": []}], "responses": {"201": {"description": "XML response"}}},
                "delete": {"summary": "XML admin delete product", "security": [{"bearerAuth": []}], "responses": {"200": {"description": "XML response"}}},
            },
            "/user/products": {
                "get": {"summary": "XML user product list", "security": [{"bearerAuth": []}], "responses": {"200": {"description": "XML response"}}}
            },
            "/products/eletronico": {"get": {"summary": "XML electronics catalog with SQL injection parameters", "parameters": catalog_query_parameters(), "responses": {"200": {"description": "XML catalog response"}}}},
            "/products/smarphone": {"get": {"summary": "XML smarphone catalog with SQL injection parameters", "parameters": catalog_query_parameters(), "responses": {"200": {"description": "XML catalog response"}}}},
            "/products/laptops": {"get": {"summary": "XML laptop catalog with SQL injection parameters", "parameters": catalog_query_parameters(), "responses": {"200": {"description": "XML catalog response"}}}},
            "/products/books": {"get": {"summary": "XML books catalog with SQL injection parameters", "parameters": catalog_query_parameters(), "responses": {"200": {"description": "XML catalog response"}}}},
            "/ecommerce/categories": {"get": {"summary": "XML e-commerce electronics categories stored in SQLite", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "XML category records"}}}},
            "/ecommerce/brands": {"get": {"summary": "XML e-commerce electronics brands stored in SQLite", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "XML brand records"}}}},
            "/ecommerce/deals": {"get": {"summary": "XML e-commerce deals and bundles", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "XML deal records"}}}},
            "/ecommerce/cart": {"get": {"summary": "XML e-commerce cart records", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "XML cart records"}}}},
            "/ecommerce/orders": {"get": {"summary": "XML e-commerce order records", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "XML order records"}}}},
            "/ecommerce/reviews": {"get": {"summary": "XML e-commerce product reviews", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "XML review records"}}}},
            "/ecommerce/warranty": {"get": {"summary": "XML e-commerce warranty plans", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "XML warranty records"}}}},
            "/ecommerce/shipping": {"get": {"summary": "XML e-commerce shipping options", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "XML shipping records"}}}},
            "/ecommerce/stores": {"get": {"summary": "XML e-commerce store pickup locations", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "XML store records"}}}},
            "/ecommerce/support": {"get": {"summary": "XML e-commerce support tickets", "parameters": ecommerce_query_parameters(), "responses": {"200": {"description": "XML support records"}}}},
            "/comments": {
                "get": {"summary": "Stored/reflected XSS comment form", "responses": {"200": {"description": "HTML form"}}},
                "post": {"summary": "Submit vulnerable comment", "responses": {"200": {"description": "HTML response with unescaped stored comment"}}},
            },
            "/audit": {"get": {"summary": "XML audit log", "responses": {"200": {"description": "XML audit events"}}}},
            "/login-tracking": {"get": {"summary": "XML authentication tracking evidence", "responses": {"200": {"description": "Login and token tracking evidence"}}}},
        },
    }


class VulnerableSoapDastHandler(server.SoapDastHandler):
    server_version = "VulnerableSoapDastLab/1.0"

    def send_json_api(self, status, data, headers=None):
        body = json.dumps(data, indent=2)
        raw = body.encode("utf-8")
        self.log_interaction_event(
            "response_sent",
            status=status,
            action=getattr(self, "_soap_action", ""),
            response_body=body,
            details={"content_type": "application/json", "response_bytes": len(raw)},
        )
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-DAST-Lab", "vulnerable-rest-json")
        self.send_header("Cache-Control", "no-store")
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def send_html(self, status, body, headers=None):
        raw = body.encode("utf-8")
        self.log_interaction_event(
            "response_sent",
            status=status,
            response_body=body,
            details={"content_type": "text/html", "response_bytes": len(raw)},
        )
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-DAST-Lab", "stored-xss-comment-form")
        self.send_header("Cache-Control", "no-store")
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def read_json_api_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
        if not raw_body.strip():
            return {}
        return json.loads(raw_body)

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
        if parsed.path == "/swagger":
            self.send_json_api(
                200,
                {
                    "rest_json": "/swagger/rest.json",
                    "xml_soap": "/swagger/xml.json",
                    "rest_base": "/api",
                    "xml_base": "/soap",
                    "xml_auth": "/soap/auth",
                    "xml_refresh_token": "/soap/refreshtoken",
                },
            )
            return
        if parsed.path == "/swagger/rest.json":
            self.send_json_api(200, rest_openapi_spec())
            return
        if parsed.path == "/swagger/xml.json":
            self.send_json_api(200, xml_openapi_spec())
            return
        if parsed.path == "/api":
            self.send_json_api(
                200,
                {
                    "name": "Vulnerable SOAP Lab REST JSON API",
                    "swagger": "/swagger/rest.json",
                    "login": "/api/login",
                    "refresh": "/api/refresh",
                    "validate": "/api/validate",
                    "admin_products": "/api/admin/products",
                    "user_products": "/api/user/products",
                    "fuzzing_products": [
                        "/api/products/eletronico",
                        "/api/products/smarphone",
                        "/api/products/laptops",
                        "/api/products/books",
                    ],
                    "ecommerce": [
                        "/api/ecommerce/categories",
                        "/api/ecommerce/brands",
                        "/api/ecommerce/deals",
                        "/api/ecommerce/cart",
                        "/api/ecommerce/orders",
                        "/api/ecommerce/reviews",
                        "/api/ecommerce/warranty",
                        "/api/ecommerce/shipping",
                        "/api/ecommerce/stores",
                        "/api/ecommerce/support",
                    ],
                    "xss_comments": "/comments",
                    "audit": "/api/audit",
                    "login_tracking": "/api/login-tracking",
                },
            )
            return
        if parsed.path == "/api/audit":
            self.send_json_api(200, {"events": server.AUDIT_LOG[-50:]})
            return
        if parsed.path == "/api/login-tracking":
            query = parse_qs(parsed.query, keep_blank_values=True)
            try:
                limit = int(query.get("limit", ["100"])[0])
            except ValueError:
                limit = 100
            limit = max(1, min(limit, 500))
            self.send_json_api(200, server.login_tracking_report(limit))
            return
        if parsed.path == "/api/validate":
            self.rest_validate_token()
            return
        if parsed.path == "/api/admin/products":
            self.rest_admin_products_list()
            return
        if parsed.path == "/api/user/products":
            self.rest_user_products_list()
            return
        category = category_slug_from_path(parsed.path, "/api/products/")
        if category:
            self.rest_fuzzing_catalog(category, parsed)
            return
        route_type = category_slug_from_path(parsed.path, "/api/ecommerce/")
        if route_type:
            self.rest_ecommerce_records(route_type, parsed)
            return
        category = category_slug_from_path(parsed.path, "/products/")
        if category:
            self.xml_fuzzing_catalog(category, parsed)
            return
        route_type = category_slug_from_path(parsed.path, "/ecommerce/")
        if route_type:
            self.xml_ecommerce_records(route_type, parsed)
            return
        if parsed.path == "/comments":
            self.render_comments_form(parsed)
            return
        if parsed.path == "/":
            self.send_json_api(
                200,
                {
                    "name": "Vulnerable SOAP DAST Lab",
                    "soap": "/soap",
                    "soap_auth": "/soap/auth",
                    "soap_refresh_token": "/soap/refreshtoken",
                    "wsdl": "/soap?wsdl",
                    "rest_json": "/api",
                    "swagger_rest_json": "/swagger/rest.json",
                    "swagger_xml_soap": "/swagger/xml.json",
                    "catalog_links": [
                        "/products/eletronico?q=camera",
                        "/products/smarphone?q=5G",
                        "/products/laptops?promotion=yes",
                        "/products/books?sort=name",
                    ],
                    "ecommerce_links": [
                        "/ecommerce/categories",
                        "/ecommerce/brands?q=orion",
                        "/ecommerce/deals?status=active",
                        "/ecommerce/cart",
                        "/ecommerce/orders",
                        "/ecommerce/reviews",
                        "/ecommerce/warranty",
                        "/ecommerce/shipping",
                        "/ecommerce/stores",
                        "/ecommerce/support",
                    ],
                    "xss_comments": "/comments",
                    "verbs": "/verbs",
                    "audit": "/audit",
                    "login_tracking": "/login-tracking",
                    "vulnerabilities": [
                        "jwt_alg_none",
                        "jwt_signature_bypass",
                        "idor",
                        "session_fixation",
                        "refresh_token_reuse",
                        "trace_reflection",
                        "unsafe_xml_reflection",
                        "sql_injection_query_reflection",
                        "stored_xss_comment_form",
                    ],
                },
            )
            return
        if parsed.path == "/soap" and "wsdl" in parse_qs(parsed.query, keep_blank_values=True):
            self.send_body(200, VULNERABLE_WSDL)
            return
        super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/login":
            self.rest_login()
            return
        if parsed.path == "/api/refresh":
            self.rest_refresh_token()
            return
        if parsed.path == "/api/admin/products":
            self.rest_admin_product_create()
            return
        if parsed.path == "/api/admin/products/push":
            self.rest_admin_product_edit()
            return
        if parsed.path == "/api/user/products":
            self.rest_user_write_forbidden("POST")
            return
        if parsed.path == "/comments":
            self.submit_comment()
            return
        if parsed.path not in {"/soap", "/soap/auth", "/soap/refreshtoken"}:
            super().do_POST()
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
        requested_action = self.headers.get("SOAPAction", "").strip('"')
        self.log_interaction_event("soap_request_received", action=requested_action, request_body=raw_body)
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
        self._soap_action = action
        if parsed.path == "/soap" and action in {"Login", "RefreshToken", "ValidateToken"}:
            required_path = "/soap/refreshtoken" if action == "RefreshToken" else "/soap/auth"
            self.log_auth_event(
                "vulnerable_soap_auth_wrong_route",
                "failure",
                error="auth_route_required",
                details={"soap_action": action, "required_path": required_path},
            )
            self.send_body(
                400,
                unsafe_response_element(
                    "AuthRouteRequired",
                    {"Action": action, "Hint": f"Use {required_path} for SOAPAction {action}."},
                ),
            )
            return
        if parsed.path == "/soap/auth" and action == "RefreshToken":
            self.log_auth_event(
                "vulnerable_soap_refresh_wrong_route",
                "failure",
                error="refresh_route_required",
                details={"soap_action": action, "required_path": "/soap/refreshtoken"},
            )
            self.send_body(
                400,
                unsafe_response_element(
                    "RefreshRouteRequired",
                    {"Action": action, "Hint": "Use /soap/refreshtoken for SOAPAction RefreshToken."},
                ),
            )
            return
        if parsed.path == "/soap/auth" and action not in {"Login", "ValidateToken"}:
            self.log_auth_event(
                "vulnerable_soap_auth_route_rejected",
                "failure",
                error="unsupported_auth_action",
                details={"soap_action": action, "allowed_actions": ["Login", "ValidateToken"]},
            )
            self.send_body(
                400,
                unsafe_response_element(
                    "UnsupportedAuthAction",
                    {"Action": action, "Hint": "/soap/auth only accepts Login or ValidateToken."},
                ),
            )
            return
        if parsed.path == "/soap/refreshtoken" and action != "RefreshToken":
            self.log_auth_event(
                "vulnerable_soap_refresh_route_rejected",
                "failure",
                error="unsupported_refresh_action",
                details={"soap_action": action, "allowed_actions": ["RefreshToken"]},
            )
            self.send_body(
                400,
                unsafe_response_element(
                    "UnsupportedRefreshAction",
                    {"Action": action, "Hint": "/soap/refreshtoken only accepts RefreshToken."},
                ),
            )
            return
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

    def do_PUSH(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/admin/products":
            self.rest_admin_product_edit()
            return
        if parsed.path == "/api/user/products":
            self.rest_user_write_forbidden("PUSH")
            return
        super().do_PUSH()

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/admin/products":
            self.rest_admin_product_delete(parsed)
            return
        if parsed.path == "/api/user/products":
            self.rest_user_write_forbidden("DELETE")
            return
        super().do_DELETE()

    def require_rest_role(self, expected_role):
        payload, error = self.require_auth()
        if error:
            return None, 401, {"error": error}
        if payload.get("role") != expected_role:
            return None, 403, {"error": "forbidden_role", "required_role": expected_role}
        return payload, None, None

    def rest_login(self):
        started_at = time.perf_counter()
        try:
            data = self.read_json_api_body()
        except json.JSONDecodeError as exc:
            self.send_json_api(400, {"error": "invalid_json", "parser_error": str(exc)})
            return
        username = str(data.get("username", ""))
        password = str(data.get("password", ""))
        user = server.USERS.get(username)
        if not user or user["password"] != password:
            self.log_auth_event(
                "vulnerable_rest_login",
                "failure",
                username=username,
                error="invalid_credentials",
                details={"duration_ms": round((time.perf_counter() - started_at) * 1000, 2)},
            )
            self.send_json_api(401, {"error": "invalid_credentials"})
            return
        access_token, refresh_token, session_id, claims = server.issue_tokens(username)
        fixed_session = self.headers.get("X-Fixed-Session-Id")
        if fixed_session:
            server.update_session_id(session_id, fixed_session)
            access_token, claims = server.make_jwt(username, user["role"], fixed_session)
            session_id = fixed_session
        refresh_record = server.get_refresh_token_record(refresh_token) or {}
        self.log_auth_event(
            "vulnerable_rest_login",
            "success",
            username=username,
            role=user["role"],
            session_id=session_id,
            token_id=claims["jti"],
            details={
                "access_token_fingerprint": server.token_fingerprint(access_token),
                "refresh_token_fingerprint": server.token_fingerprint(refresh_token),
                "access_token_expires_at": claims["exp"],
                "access_token_ttl_seconds": server.ACCESS_TOKEN_TTL_SECONDS,
                "refresh_token_expires_at": refresh_record.get("expires_at"),
                "refresh_token_ttl_seconds": server.REFRESH_TOKEN_TTL_SECONDS,
                "session_fixation_used": bool(fixed_session),
                "duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
            },
        )
        self.send_json_api(
            200,
            {
                "accessToken": access_token,
                "refreshToken": refresh_token,
                "sessionId": session_id,
                "expiresAt": claims["exp"],
                "tokenId": claims["jti"],
                "vulnerableMode": True,
            },
            headers={"Set-Cookie": f"DASTSESSION={session_id}; Path=/"},
        )

    def rest_refresh_token(self):
        started_at = time.perf_counter()
        try:
            data = self.read_json_api_body()
        except json.JSONDecodeError as exc:
            self.send_json_api(400, {"error": "invalid_json", "parser_error": str(exc)})
            return
        refresh_token = str(data.get("refreshToken") or data.get("refresh_token") or "")
        record = server.get_refresh_token_record(refresh_token)
        if not record:
            self.log_auth_event(
                "vulnerable_rest_refresh_token",
                "failure",
                error="refresh_token_not_found",
                details={
                    "refresh_token_fingerprint": server.token_fingerprint(refresh_token),
                    "duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
                },
            )
            self.send_json_api(401, {"error": "refresh_token_not_found"})
            return
        if int(time.time()) >= int(record.get("expires_at", 0)):
            self.log_auth_event(
                "vulnerable_rest_refresh_token",
                "failure",
                error="refresh_token_expired",
                username=record.get("username"),
                session_id=record.get("session_id"),
                details={
                    "refresh_token_fingerprint": server.token_fingerprint(refresh_token),
                    "refresh_token_expires_at": record.get("expires_at"),
                    "duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
                },
            )
            self.send_json_api(401, {"error": "refresh_token_expired"})
            return
        user = server.USERS[record["username"]]
        access_token, claims = server.make_jwt(record["username"], user["role"], record["session_id"])
        self.log_auth_event(
            "vulnerable_rest_refresh_token",
            "success",
            username=record["username"],
            role=user["role"],
            session_id=record["session_id"],
            token_id=claims["jti"],
            details={
                "refresh_token_fingerprint": server.token_fingerprint(refresh_token),
                "new_access_token_fingerprint": server.token_fingerprint(access_token),
                "new_access_token_expires_at": claims["exp"],
                "refresh_token_expires_at": record.get("expires_at"),
                "refresh_rotated": False,
                "vulnerability": "refresh_token_reuse_allowed",
                "duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
            },
        )
        self.send_json_api(
            200,
            {
                "accessToken": access_token,
                "refreshToken": refresh_token,
                "sessionId": record["session_id"],
                "expiresAt": claims["exp"],
                "tokenId": claims["jti"],
                "rotated": False,
                "vulnerability": "refresh token reuse allowed",
            },
        )

    def rest_validate_token(self):
        payload, error = self.require_auth()
        if error:
            self.send_json_api(401, {"error": error})
            return
        self.send_json_api(
            200,
            {
                "subject": payload.get("sub"),
                "role": payload.get("role"),
                "sessionId": payload.get("sid"),
                "tokenId": payload.get("jti"),
                "expiresAt": payload.get("exp"),
                "vulnerability": "signature and session binding may be bypassed",
            },
        )

    def rest_admin_products_list(self):
        payload, status, error = self.require_rest_role("admin")
        if error:
            self.send_json_api(status, error)
            return
        self.send_json_api(
            200,
            {
                "path": "/api/admin/products",
                "authenticatedAs": payload.get("sub"),
                "products": [product_for_admin(sku, product) for sku, product in server.PRODUCTS.items()],
            },
        )

    def rest_user_products_list(self):
        payload, status, error = self.require_rest_role("user")
        if error:
            self.send_json_api(status, error)
            return
        self.send_json_api(
            200,
            {
                "path": "/api/user/products",
                "authenticatedAs": payload.get("sub"),
                "catalog": [product_for_user(sku, product) for sku, product in server.PRODUCTS.items()],
            },
        )

    def rest_fuzzing_catalog(self, category, parsed):
        query = parse_qs(parsed.query, keep_blank_values=True)
        if not server.catalog_category_exists(category):
            self.send_json_api(404, {"error": "category_not_found", "category": category})
            return
        injected = looks_like_sql_injection(query)
        products = server.catalog_products(category, query, return_all=injected)
        self.send_json_api(
            200,
            {
                "path": parsed.path,
                "category": category,
                "storage": "sqlite",
                "database": server.DB_PATH,
                "count": len(products),
                "products": products,
                "query": {key: values[0] if values else "" for key, values in query.items()},
                "vulnerableSql": vulnerable_catalog_sql(category, query),
                "sqlInjectionAccepted": injected,
                "warning": "Intentional lab behavior: query parameters are concatenated into a simulated SQL statement.",
            },
        )

    def xml_fuzzing_catalog(self, category, parsed):
        query = parse_qs(parsed.query, keep_blank_values=True)
        if not server.catalog_category_exists(category):
            self.send_body(404, server.xml_document("response", {"error": "category_not_found", "category": category}))
            return
        injected = looks_like_sql_injection(query)
        products = server.catalog_products(category, query, return_all=injected)
        self.send_body(
            200,
            server.xml_document(
                "response",
                {
                    "path": parsed.path,
                    "category": category,
                    "storage": "sqlite",
                    "database": server.DB_PATH,
                    "count": len(products),
                    "products": products,
                    "query": {key: values[0] if values else "" for key, values in query.items()},
                    "vulnerableSql": vulnerable_catalog_sql(category, query),
                    "sqlInjectionAccepted": injected,
                    "warning": "Intentional lab behavior: query parameters are concatenated into a simulated SQL statement.",
                },
            ),
        )

    def rest_ecommerce_records(self, route_type, parsed):
        query = parse_qs(parsed.query, keep_blank_values=True)
        if not server.ecommerce_route_exists(route_type):
            self.send_json_api(404, {"error": "ecommerce_route_not_found", "route": route_type})
            return
        records = server.ecommerce_records(route_type, query)
        self.send_json_api(
            200,
            {
                "path": parsed.path,
                "route": route_type,
                "storage": "sqlite",
                "database": server.DB_PATH,
                "count": len(records),
                "records": records,
                "query": {key: values[0] if values else "" for key, values in query.items()},
            },
        )

    def xml_ecommerce_records(self, route_type, parsed):
        query = parse_qs(parsed.query, keep_blank_values=True)
        if not server.ecommerce_route_exists(route_type):
            self.send_body(404, server.xml_document("response", {"error": "ecommerce_route_not_found", "route": route_type}))
            return
        records = server.ecommerce_records(route_type, query)
        self.send_body(
            200,
            server.xml_document(
                "response",
                {
                    "path": parsed.path,
                    "route": route_type,
                    "storage": "sqlite",
                    "database": server.DB_PATH,
                    "count": len(records),
                    "records": records,
                    "query": {key: values[0] if values else "" for key, values in query.items()},
                },
            ),
        )

    def render_comments_form(self, parsed):
        query = parse_qs(parsed.query, keep_blank_values=True)
        reflected = query.get("preview", [""])[0]
        comments = "\n".join(
            f"<article class=\"comment\"><strong>{item['name']}</strong><p>{item['comment']}</p></article>"
            for item in server.recent_comments(25)
        )
        html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Vulnerable Comment Lab</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; max-width: 920px; }}
    label {{ display: block; margin-top: 12px; font-weight: 700; }}
    input, textarea {{ width: 100%; padding: 10px; margin-top: 4px; }}
    button {{ margin-top: 12px; padding: 10px 14px; }}
    .comment {{ border: 1px solid #ccc; padding: 12px; margin: 12px 0; }}
    .preview {{ background: #fff7d6; padding: 12px; margin: 12px 0; }}
  </style>
</head>
<body>
  <h1>Vulnerable Comment Lab</h1>
  <nav>
    <a href="/products/eletronico?q=camera">eletronico</a> |
    <a href="/products/smarphone?q=5G">smarphone</a> |
    <a href="/products/laptops?promotion=yes">laptops</a> |
    <a href="/products/books?q=SQL">books</a>
  </nav>
  <p>This page is intentionally vulnerable to stored and reflected XSS for authorized DAST testing.</p>
  <section class="preview">Preview: {reflected}</section>
  <form method="POST" action="/comments">
    <label>Name</label>
    <input name="name" value="security-tester">
    <label>Comment</label>
    <textarea name="comment" rows="5"><script>alert('xss-lab')</script></textarea>
    <button type="submit">Send comment</button>
  </form>
  <h2>Stored comments</h2>
  {comments}
</body>
</html>"""
        self.send_html(200, html)

    def submit_comment(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
        data = parse_qs(raw_body, keep_blank_values=True)
        name = data.get("name", ["anonymous"])[0]
        comment = data.get("comment", [""])[0]
        server.add_comment(name, comment)
        self.render_comments_form(urlparse("/comments?preview=" + comment))

    def rest_admin_product_create(self):
        payload, status, error = self.require_rest_role("admin")
        if error:
            self.send_json_api(status, error)
            return
        try:
            data = self.read_json_api_body()
            sku = str(data.get("sku", "")).strip()
            name = str(data.get("name", "")).strip()
            price = float(data.get("price"))
            stock = int(data.get("stock", 0))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            self.send_json_api(400, {"error": "invalid_json", "parser_error": str(exc)})
            return
        if not sku or not name:
            self.send_json_api(400, {"error": "missing_required_fields"})
            return
        if sku in server.PRODUCTS:
            self.send_json_api(409, {"error": "product_already_exists", "sku": sku})
            return
        server.PRODUCTS[sku] = {"name": name, "price": round(price, 2), "stock": stock}
        self.send_json_api(201, {"createdBy": payload.get("sub"), "product": product_for_admin(sku, server.PRODUCTS[sku])})

    def rest_admin_product_edit(self):
        payload, status, error = self.require_rest_role("admin")
        if error:
            self.send_json_api(status, error)
            return
        try:
            data = self.read_json_api_body()
            sku = str(data.get("sku", "")).strip()
        except json.JSONDecodeError as exc:
            self.send_json_api(400, {"error": "invalid_json", "parser_error": str(exc)})
            return
        if sku not in server.PRODUCTS:
            self.send_json_api(404, {"error": "product_not_found", "sku": sku})
            return
        before = product_for_admin(sku, server.PRODUCTS[sku])
        if "name" in data:
            server.PRODUCTS[sku]["name"] = str(data["name"])
        if "price" in data:
            server.PRODUCTS[sku]["price"] = round(float(data["price"]), 2)
        if "stock" in data:
            server.PRODUCTS[sku]["stock"] = int(data["stock"])
        self.send_json_api(
            200,
            {
                "method": self.command,
                "updatedBy": payload.get("sub"),
                "before": before,
                "after": product_for_admin(sku, server.PRODUCTS[sku]),
            },
        )

    def rest_admin_product_delete(self, parsed):
        payload, status, error = self.require_rest_role("admin")
        if error:
            self.send_json_api(status, error)
            return
        sku = parse_qs(parsed.query, keep_blank_values=True).get("sku", [""])[0]
        if not sku:
            try:
                sku = str(self.read_json_api_body().get("sku", ""))
            except json.JSONDecodeError as exc:
                self.send_json_api(400, {"error": "invalid_json", "parser_error": str(exc)})
                return
        if sku not in server.PRODUCTS:
            self.send_json_api(404, {"error": "product_not_found", "sku": sku})
            return
        deleted = server.PRODUCTS.pop(sku)
        self.send_json_api(200, {"deletedBy": payload.get("sub"), "deleted": product_for_admin(sku, deleted)})

    def rest_user_write_forbidden(self, method):
        payload, error = self.require_auth()
        if error:
            self.send_json_api(401, {"error": error})
            return
        self.send_json_api(
            403,
            {
                "error": "forbidden_method",
                "role": payload.get("role"),
                "method": method,
                "allowedMethods": ["GET"],
            },
        )

    def require_auth(self):
        token = self.bearer_token() or self.headers.get("X-Session-Token", "")
        if not token:
            self.log_auth_event("vulnerable_access_token_missing", "failure", error="missing_bearer_token")
            return None, "missing_bearer_token"
        payload, error = insecure_verify_jwt(token)
        if error:
            self.log_auth_event(
                "vulnerable_access_token_validation",
                "failure",
                error=error,
                details={"access_token_fingerprint": server.token_fingerprint(token)},
            )
            return None, error
        # Vulnerability: cookie/session binding is not enforced.
        self.log_auth_event(
            "vulnerable_access_token_validation",
            "success",
            username=payload.get("sub"),
            role=payload.get("role"),
            session_id=payload.get("sid"),
            token_id=payload.get("jti"),
            details={
                "access_token_fingerprint": server.token_fingerprint(token),
                "signature_verified": False,
                "session_cookie_enforced": False,
            },
        )
        return payload, None

    def soap_login(self, root):
        started_at = time.perf_counter()
        username = server.xml_text(root, "Username")
        password = server.xml_text(root, "Password")
        user = server.USERS.get(username)
        if not user or user["password"] != password:
            self.log_auth_event(
                "vulnerable_login",
                "failure",
                username=username,
                error="invalid_credentials",
                details={"duration_ms": round((time.perf_counter() - started_at) * 1000, 2)},
            )
            self.send_body(401, server.soap_fault("Auth.InvalidCredentials", "Invalid username or password"))
            return

        access_token, refresh_token, session_id, claims = server.issue_tokens(username)
        fixed_session = self.headers.get("X-Fixed-Session-Id")
        if fixed_session:
            # Vulnerability: session fixation through attacker-supplied session id.
            server.update_session_id(session_id, fixed_session)
            access_token, claims = server.make_jwt(username, user["role"], fixed_session)
            session_id = fixed_session
        refresh_record = server.get_refresh_token_record(refresh_token) or {}
        self.log_auth_event(
            "vulnerable_login",
            "success",
            username=username,
            role=user["role"],
            session_id=session_id,
            token_id=claims["jti"],
            details={
                "access_token_fingerprint": server.token_fingerprint(access_token),
                "refresh_token_fingerprint": server.token_fingerprint(refresh_token),
                "access_token_expires_at": claims["exp"],
                "access_token_ttl_seconds": server.ACCESS_TOKEN_TTL_SECONDS,
                "refresh_token_expires_at": refresh_record.get("expires_at"),
                "refresh_token_ttl_seconds": server.REFRESH_TOKEN_TTL_SECONDS,
                "session_fixation_used": bool(fixed_session),
                "cookie_security_attributes": "missing_httponly_samesite",
                "duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
            },
        )

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
        started_at = time.perf_counter()
        refresh_token = server.xml_text(root, "RefreshToken")
        refresh_token_source = "soap_body"
        if not refresh_token.strip():
            wrapped_string = server.xml_text(root, "String").strip()
            if wrapped_string:
                refresh_token = wrapped_string
                refresh_token_source = "wrapped_string_body"
        record = server.get_refresh_token_record(refresh_token)
        if not record:
            bearer = self.bearer_token()
            if bearer:
                payload, bearer_error = insecure_verify_jwt(bearer)
                if payload:
                    fallback_token, fallback_record = server.get_active_refresh_token_for_session(
                        payload.get("sub", ""),
                        payload.get("sid", ""),
                    )
                    if fallback_token and fallback_record:
                        refresh_token = fallback_token
                        record = fallback_record
                        refresh_token_source = "authorization_bearer_session_fallback"
                elif not refresh_token.strip():
                    refresh_token_source = f"missing_body_token_bearer_{bearer_error}"
        if not record:
            self.log_auth_event(
                "vulnerable_refresh_token",
                "failure",
                error="refresh_token_not_found",
                details={
                    "refresh_token_fingerprint": server.token_fingerprint(refresh_token),
                    "refresh_token_source": refresh_token_source,
                    "body_refresh_token_present": bool(refresh_token.strip()),
                    "duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
                },
            )
            self.send_body(401, server.soap_fault("Auth.RefreshFailed", "refresh_token_not_found"))
            return
        if int(time.time()) >= int(record.get("expires_at", 0)):
            self.log_auth_event(
                "vulnerable_refresh_token",
                "failure",
                error="refresh_token_expired",
                username=record.get("username"),
                session_id=record.get("session_id"),
                details={
                    "refresh_token_fingerprint": server.token_fingerprint(refresh_token),
                    "refresh_token_source": refresh_token_source,
                    "refresh_token_expires_at": record.get("expires_at"),
                    "duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
                },
            )
            self.send_body(401, server.soap_fault("Auth.RefreshFailed", "refresh_token_expired"))
            return

        # Vulnerability: refresh token is reusable and not rotated.
        user = server.USERS[record["username"]]
        access_token, claims = server.make_jwt(record["username"], user["role"], record["session_id"])
        self.log_auth_event(
            "vulnerable_refresh_token",
            "success",
            username=record["username"],
            role=user["role"],
            session_id=record["session_id"],
            token_id=claims["jti"],
            details={
                "refresh_token_fingerprint": server.token_fingerprint(refresh_token),
                "refresh_token_source": refresh_token_source,
                "new_access_token_fingerprint": server.token_fingerprint(access_token),
                "new_access_token_expires_at": claims["exp"],
                "refresh_token_expires_at": record.get("expires_at"),
                "refresh_rotated": False,
                "vulnerability": "refresh_token_reuse_allowed",
                "duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
            },
        )
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
            self.log_auth_event("vulnerable_validate_token", "failure", error=error)
            self.send_body(401, server.soap_fault("Auth.TokenInvalid", error))
            return
        self.log_auth_event(
            "vulnerable_validate_token",
            "success",
            username=payload.get("sub"),
            role=payload.get("role"),
            session_id=payload.get("sid"),
            token_id=payload.get("jti"),
        )
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
