#!/usr/bin/env python3
import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from xml.etree import ElementTree

try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None


HOST = os.environ.get("SOAP_DAST_HOST", "127.0.0.1")
PORT = int(os.environ.get("SOAP_DAST_PORT", "8088"))
PUBLIC_HOST = os.environ.get("SOAP_DAST_PUBLIC_HOST", HOST)
PUBLIC_PORT = int(os.environ.get("SOAP_DAST_PUBLIC_PORT", str(PORT)))
JWT_SECRET = "change-me-only-for-this-dast-lab"
JWT_ISSUER = "soap-dast-lab"
ACCESS_TOKEN_TTL_SECONDS = 120
REFRESH_TOKEN_TTL_SECONDS = 900
SESSION_TTL_SECONDS = 600
LOCAL_TIMEZONE_NAME = os.environ.get("SOAP_DAST_TIMEZONE", "America/Sao_Paulo")
DB_PATH = os.environ.get("SOAP_DAST_DB_PATH", "/tmp/rest_soap_labs.db")

USERS = {
    "admin_aurora": {
        "password": "adminpass1",
        "role": "admin",
        "account_id": "9001",
        "balance": 99250.00,
    },
    "admin_boreal": {
        "password": "adminpass2",
        "role": "admin",
        "account_id": "9002",
        "balance": 87410.20,
    },
    "admin_cosmos": {
        "password": "adminpass3",
        "role": "admin",
        "account_id": "9003",
        "balance": 76500.75,
    },
    "admin_delta": {
        "password": "adminpass4",
        "role": "admin",
        "account_id": "9004",
        "balance": 68220.40,
    },
    "admin_equinox": {
        "password": "adminpass5",
        "role": "admin",
        "account_id": "9005",
        "balance": 59100.10,
    },
    "user_apollo": {
        "password": "userpass1",
        "role": "user",
        "account_id": "1001",
        "balance": 1280.50,
    },
    "user_bianca": {
        "password": "userpass2",
        "role": "user",
        "account_id": "1002",
        "balance": 940.25,
    },
    "user_cairo": {
        "password": "userpass3",
        "role": "user",
        "account_id": "1003",
        "balance": 2100.00,
    },
    "user_diana": {
        "password": "userpass4",
        "role": "user",
        "account_id": "1004",
        "balance": 315.90,
    },
    "user_elias": {
        "password": "userpass5",
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

FUZZING_CATALOG = {
    "eletronico": [
        {"name": "Camera Sentinel 4K", "description": "Camera IP com visao noturna e audio bidirecional", "value": 899.90, "stock": 14, "promotion": "yes"},
        {"name": "Roteador Prisma AX3000", "description": "Roteador Wi-Fi 6 para laboratorio e pequenos escritorios", "value": 649.00, "stock": 32, "promotion": "no"},
        {"name": "Headset Vector USB", "description": "Headset com microfone removivel e cancelamento passivo", "value": 219.90, "stock": 77, "promotion": "yes"},
        {"name": "Webcam Aurora HD", "description": "Webcam 1080p para reunioes e transmissao", "value": 189.50, "stock": 41, "promotion": "no"},
        {"name": "Hub Quantum USB-C", "description": "Hub com HDMI, rede gigabit e leitor SD", "value": 299.90, "stock": 25, "promotion": "yes"},
        {"name": "Carregador Nimbus 65W", "description": "Carregador GaN com duas portas USB-C", "value": 159.90, "stock": 64, "promotion": "no"},
        {"name": "Caixa Som Pulse Mini", "description": "Caixa Bluetooth compacta resistente a agua", "value": 239.00, "stock": 38, "promotion": "yes"},
        {"name": "Projetor Vega Pico", "description": "Projetor portatil para salas pequenas", "value": 1299.00, "stock": 9, "promotion": "no"},
        {"name": "Switch Atlas 8 Portas", "description": "Switch gigabit nao gerenciavel para bancada", "value": 179.90, "stock": 53, "promotion": "yes"},
        {"name": "Controle Terra Gamepad", "description": "Controle sem fio para PC e mobile", "value": 269.90, "stock": 28, "promotion": "no"},
    ],
    "smarphone": [
        {"name": "Smarphone Orion X1", "description": "Tela OLED, 128 GB e camera dupla", "value": 1899.90, "stock": 22, "promotion": "yes"},
        {"name": "Smarphone Boreal Lite", "description": "Modelo de entrada com bateria de longa duracao", "value": 899.00, "stock": 46, "promotion": "no"},
        {"name": "Smarphone Cosmos Pro", "description": "Camera tripla, 256 GB e carregamento rapido", "value": 3299.90, "stock": 11, "promotion": "yes"},
        {"name": "Smarphone Delta Max", "description": "Tela grande para produtividade e streaming", "value": 2499.00, "stock": 18, "promotion": "no"},
        {"name": "Smarphone Equinox Mini", "description": "Aparelho compacto com NFC", "value": 1399.90, "stock": 33, "promotion": "yes"},
        {"name": "Smarphone Apollo 5G", "description": "Conectividade 5G e 8 GB RAM", "value": 2199.90, "stock": 27, "promotion": "no"},
        {"name": "Smarphone Bianca Plus", "description": "Selfie camera de alta resolucao", "value": 1799.00, "stock": 20, "promotion": "yes"},
        {"name": "Smarphone Cairo Play", "description": "Otimizado para jogos casuais", "value": 1599.90, "stock": 39, "promotion": "no"},
        {"name": "Smarphone Diana Secure", "description": "Recursos extras de privacidade e biometria", "value": 2799.00, "stock": 13, "promotion": "yes"},
        {"name": "Smarphone Elias Go", "description": "Dual SIM e armazenamento expansivel", "value": 1099.90, "stock": 51, "promotion": "no"},
    ],
    "laptops": [
        {"name": "Laptop Orion 14", "description": "Ultrabook leve com 16 GB RAM", "value": 4299.90, "stock": 18, "promotion": "yes"},
        {"name": "Laptop Nebula 15", "description": "Notebook para desenvolvimento e virtualizacao", "value": 5599.00, "stock": 8, "promotion": "no"},
        {"name": "Laptop Atlas Pro", "description": "CPU de alto desempenho e SSD 1 TB", "value": 7899.90, "stock": 6, "promotion": "yes"},
        {"name": "Laptop Pulse Air", "description": "Modelo fino para viagens", "value": 3799.00, "stock": 21, "promotion": "no"},
        {"name": "Laptop Vega Work", "description": "Foco em planilhas e ferramentas corporativas", "value": 3199.90, "stock": 30, "promotion": "yes"},
        {"name": "Laptop Sentinel Sec", "description": "Modulo TPM e leitor biometrico", "value": 6499.00, "stock": 7, "promotion": "no"},
        {"name": "Laptop Prisma Edu", "description": "Equipamento para laboratorios educacionais", "value": 2499.90, "stock": 44, "promotion": "yes"},
        {"name": "Laptop Quantum Studio", "description": "GPU dedicada para edicao e criacao", "value": 8999.00, "stock": 5, "promotion": "no"},
        {"name": "Laptop Nimbus Basic", "description": "Notebook simples para navegacao", "value": 1999.90, "stock": 58, "promotion": "yes"},
        {"name": "Laptop Terra Rugged", "description": "Chassi reforcado para campo", "value": 7199.00, "stock": 4, "promotion": "no"},
    ],
    "books": [
        {"name": "Secure Coding Kids", "description": "Introducao simples a desenvolvimento seguro", "value": 79.90, "stock": 80, "promotion": "yes"},
        {"name": "SOAP APIs Explained", "description": "Guia pratico de servicos SOAP", "value": 129.90, "stock": 24, "promotion": "no"},
        {"name": "JWT Field Notes", "description": "Notas sobre tokens, sessoes e refresh", "value": 99.00, "stock": 35, "promotion": "yes"},
        {"name": "DAST Lab Manual", "description": "Manual de testes dinamicos autorizados", "value": 149.90, "stock": 17, "promotion": "no"},
        {"name": "XML Parser Tales", "description": "Historias tecnicas sobre XML e validacao", "value": 89.90, "stock": 48, "promotion": "yes"},
        {"name": "API Threat Modeling", "description": "Modelagem de ameacas para APIs modernas", "value": 159.00, "stock": 20, "promotion": "no"},
        {"name": "Fuzzing Playground", "description": "Exercicios de fuzzing para iniciantes", "value": 119.90, "stock": 26, "promotion": "yes"},
        {"name": "Cloud Containers 101", "description": "Fundamentos de containers em cloud", "value": 109.90, "stock": 31, "promotion": "no"},
        {"name": "XSS Patterns", "description": "Catalogo de padroes de cross-site scripting", "value": 139.90, "stock": 12, "promotion": "yes"},
        {"name": "SQL Injection Primer", "description": "Conceitos basicos de injecao SQL em labs", "value": 94.90, "stock": 42, "promotion": "no"},
    ],
}

COMMENTS = []

ECOMMERCE_RECORDS = [
    {"route_type": "categories", "slug": "audio-video", "title": "Audio e Video", "description": "TVs, soundbars, webcams, projetores e caixas inteligentes", "value": 0, "stock": 320, "status": "active", "metadata": "crawl_priority=high"},
    {"route_type": "categories", "slug": "smart-home", "title": "Casa Inteligente", "description": "Sensores, cameras, fechaduras e automacao residencial", "value": 0, "stock": 180, "status": "active", "metadata": "crawl_priority=high"},
    {"route_type": "categories", "slug": "energia", "title": "Energia e Carregadores", "description": "Nobreaks, carregadores, baterias e filtros de linha", "value": 0, "stock": 260, "status": "active", "metadata": "crawl_priority=medium"},
    {"route_type": "brands", "slug": "orion", "title": "Orion Labs", "description": "Marca de notebooks, monitores e perifericos premium", "value": 0, "stock": 95, "status": "preferred", "metadata": "vendor_id=OR-001"},
    {"route_type": "brands", "slug": "nebula", "title": "Nebula Devices", "description": "Linha gamer e entretenimento conectado", "value": 0, "stock": 130, "status": "active", "metadata": "vendor_id=NB-002"},
    {"route_type": "brands", "slug": "sentinel", "title": "Sentinel Secure", "description": "Equipamentos com foco em seguranca fisica e digital", "value": 0, "stock": 72, "status": "active", "metadata": "vendor_id=SE-003"},
    {"route_type": "deals", "slug": "flash-camera-4k", "title": "Oferta Camera 4K", "description": "Desconto relampago em cameras IP 4K", "value": 699.90, "stock": 12, "status": "expires_today", "metadata": "coupon=CAMERA20"},
    {"route_type": "deals", "slug": "kit-home-office", "title": "Kit Home Office", "description": "Monitor, webcam, teclado e headset em pacote", "value": 2499.90, "stock": 8, "status": "active", "metadata": "bundle_id=KIT-442"},
    {"route_type": "cart", "slug": "cart-demo-1001", "title": "Carrinho Demo 1001", "description": "Carrinho de teste com notebook, mouse e garantia", "value": 4759.70, "stock": 3, "status": "open", "metadata": "owner=user_apollo"},
    {"route_type": "orders", "slug": "order-2026-9001", "title": "Pedido 2026-9001", "description": "Pedido de laboratorio para rastreamento DAST", "value": 3299.90, "stock": 1, "status": "processing", "metadata": "tracking=BR-LAB-9001"},
    {"route_type": "reviews", "slug": "review-monitor-nebula", "title": "Review Monitor Nebula", "description": "Otimo brilho, resposta rapida e base estavel", "value": 4.8, "stock": 1, "status": "published", "metadata": "rating=4.8"},
    {"route_type": "warranty", "slug": "warranty-laptop-orion", "title": "Garantia Laptop Orion", "description": "Plano estendido de 24 meses com suporte prioritario", "value": 399.90, "stock": 45, "status": "available", "metadata": "term_months=24"},
    {"route_type": "shipping", "slug": "shipping-express-sp", "title": "Entrega Express Sao Paulo", "description": "Entrega no mesmo dia para itens em estoque", "value": 29.90, "stock": 100, "status": "available", "metadata": "sla_hours=8"},
    {"route_type": "stores", "slug": "store-east-lab", "title": "Loja East Lab", "description": "Unidade de retirada para equipamentos eletronicos", "value": 0, "stock": 520, "status": "open", "metadata": "region=eastus"},
    {"route_type": "support", "slug": "ticket-power-001", "title": "Ticket Nobreak", "description": "Chamado de suporte sobre autonomia de nobreak", "value": 0, "stock": 1, "status": "waiting_customer", "metadata": "severity=medium"},
]

REFRESH_TOKENS = {}
SESSIONS = {}
AUDIT_LOG = []
SENSITIVE_XML_TAGS = {"Password", "AccessToken", "RefreshToken"}
SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie"}
LOGIN_TRACKING_EVENT_MARKERS = {
    "login",
    "refresh_token",
    "validate_token",
    "access_token",
    "token_expired",
    "session_expired",
    "session_not_found",
    "refresh",
}
LOGIN_TRACKING_PATHS = {
    "/soap/auth",
    "/soap/refreshtoken",
    "/api/login",
    "/api/refresh",
    "/api/validate",
    "/api/logout",
}

LOGIN_AUDIT_PATHS = {
    "/soap/auth",
    "/soap/refreshtoken",
    "/soap",
    "/api/login",
    "/api/refresh",
    "/api/logout",
}

LOGIN_AUDIT_AUTH_EVENTS = {
    "lab_login",
    "lab_rest_login",
    "lab_refresh_token",
    "lab_rest_refresh_token",
    "logout",
    "rest_logout",
}


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(value):
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def now():
    return int(time.time())


def db_connect():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def execute_with_db_retry(operation, attempts=5, delay=0.25):
    last_error = None
    for attempt in range(attempts):
        try:
            return operation()
        except sqlite3.OperationalError as exc:
            last_error = exc
            if "locked" not in str(exc).lower() or attempt == attempts - 1:
                raise
            time.sleep(delay * (attempt + 1))
    if last_error:
        raise last_error
    return None


def row_to_dict(row):
    data = dict(row)
    for key in ("value",):
        if key in data:
            data[key] = float(data[key])
    return data


def init_database():
    def initialize():
        with db_connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS catalog_products (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    value REAL NOT NULL,
                    stock INTEGER NOT NULL,
                    promotion TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    comment TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ecommerce_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    route_type TEXT NOT NULL,
                    slug TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    value REAL NOT NULL,
                    stock INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    metadata TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    client TEXT,
                    path TEXT,
                    payload TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    refresh_token TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    active INTEGER NOT NULL
                )
                """
            )
            seed_database(conn)

    execute_with_db_retry(initialize, attempts=8, delay=0.5)


def seed_database(conn):
    if conn.execute("SELECT COUNT(*) FROM catalog_products").fetchone()[0] == 0:
        for category, products in FUZZING_CATALOG.items():
            conn.executemany(
                """
                INSERT INTO catalog_products (category, name, description, value, stock, promotion)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        category,
                        product["name"],
                        product["description"],
                        product["value"],
                        product["stock"],
                        product["promotion"],
                    )
                    for product in products
                ],
            )
    if conn.execute("SELECT COUNT(*) FROM ecommerce_records").fetchone()[0] == 0:
        conn.executemany(
            """
            INSERT INTO ecommerce_records (route_type, slug, title, description, value, stock, status, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    item["route_type"],
                    item["slug"],
                    item["title"],
                    item["description"],
                    item["value"],
                    item["stock"],
                    item["status"],
                    item["metadata"],
                )
                for item in ECOMMERCE_RECORDS
            ],
        )


def catalog_category_exists(category):
    with db_connect() as conn:
        row = conn.execute("SELECT 1 FROM catalog_products WHERE category = ? LIMIT 1", (category,)).fetchone()
        return row is not None


def catalog_products(category, query=None, return_all=False):
    query = query or {}
    params = [category]
    sql = "SELECT name, description, value, stock, promotion FROM catalog_products WHERE category = ?"
    if not return_all:
        search = query.get("q", [""])[0]
        promotion = query.get("promotion", [""])[0]
        min_value = query.get("min_value", [""])[0]
        if search:
            sql += " AND (LOWER(name) LIKE ? OR LOWER(description) LIKE ?)"
            like = f"%{search.lower()}%"
            params.extend([like, like])
        if promotion in {"yes", "no"}:
            sql += " AND promotion = ?"
            params.append(promotion)
        if min_value:
            try:
                sql += " AND value >= ?"
                params.append(float(min_value))
            except ValueError:
                pass
    sort = query.get("sort", ["name"])[0]
    if sort in {"name", "value", "stock", "promotion"}:
        sql += f" ORDER BY {sort}"
    else:
        sql += " ORDER BY name"
    with db_connect() as conn:
        return [row_to_dict(row) for row in conn.execute(sql, params).fetchall()]


def add_comment(name, comment):
    created_at = now()
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO comments (name, comment, created_at) VALUES (?, ?, ?)",
            (name, comment, created_at),
        )
    return created_at


def recent_comments(limit=25):
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT name, comment, created_at FROM comments ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [row_to_dict(row) for row in rows]


def ecommerce_records(route_type, query=None):
    query = query or {}
    params = [route_type]
    sql = "SELECT slug, title, description, value, stock, status, metadata FROM ecommerce_records WHERE route_type = ?"
    search = query.get("q", [""])[0]
    status = query.get("status", [""])[0]
    if search:
        sql += " AND (LOWER(title) LIKE ? OR LOWER(description) LIKE ? OR LOWER(metadata) LIKE ?)"
        like = f"%{search.lower()}%"
        params.extend([like, like, like])
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY title"
    with db_connect() as conn:
        return [row_to_dict(row) for row in conn.execute(sql, params).fetchall()]


def ecommerce_route_exists(route_type):
    with db_connect() as conn:
        row = conn.execute("SELECT 1 FROM ecommerce_records WHERE route_type = ? LIMIT 1", (route_type,)).fetchone()
        return row is not None


def save_session(session_id, username, created_at, expires_at):
    SESSIONS[session_id] = {"username": username, "created_at": created_at, "expires_at": expires_at}
    with db_connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO sessions (session_id, username, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (session_id, username, created_at, expires_at),
        )


def get_session(session_id):
    if session_id in SESSIONS:
        return SESSIONS[session_id]
    with db_connect() as conn:
        row = conn.execute(
            "SELECT username, created_at, expires_at FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
    if not row:
        return None
    session = {"username": row["username"], "created_at": int(row["created_at"]), "expires_at": int(row["expires_at"])}
    SESSIONS[session_id] = session
    return session


def delete_session(session_id):
    SESSIONS.pop(session_id, None)
    with db_connect() as conn:
        conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))


def update_session_id(old_session_id, new_session_id):
    session = get_session(old_session_id)
    if not session:
        return None
    delete_session(old_session_id)
    save_session(new_session_id, session["username"], session["created_at"], session["expires_at"])
    with db_connect() as conn:
        conn.execute("UPDATE refresh_tokens SET session_id = ? WHERE session_id = ?", (new_session_id, old_session_id))
    for record in REFRESH_TOKENS.values():
        if record.get("session_id") == old_session_id:
            record["session_id"] = new_session_id
    return get_session(new_session_id)


def save_refresh_token(refresh_token, username, session_id, expires_at, active=True):
    REFRESH_TOKENS[refresh_token] = {
        "username": username,
        "session_id": session_id,
        "expires_at": expires_at,
        "active": bool(active),
    }
    with db_connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO refresh_tokens (refresh_token, username, session_id, expires_at, active)
            VALUES (?, ?, ?, ?, ?)
            """,
            (refresh_token, username, session_id, expires_at, 1 if active else 0),
        )


def get_refresh_token_record(refresh_token):
    if refresh_token in REFRESH_TOKENS:
        return REFRESH_TOKENS[refresh_token]
    with db_connect() as conn:
        row = conn.execute(
            "SELECT username, session_id, expires_at, active FROM refresh_tokens WHERE refresh_token = ?",
            (refresh_token,),
        ).fetchone()
    if not row:
        portable_record = verify_portable_refresh_token(refresh_token)
        if portable_record:
            REFRESH_TOKENS[refresh_token] = portable_record
            save_session(
                portable_record["session_id"],
                portable_record["username"],
                now(),
                max(now() + SESSION_TTL_SECONDS, int(portable_record["expires_at"])),
            )
            return portable_record
        return None
    record = {
        "username": row["username"],
        "session_id": row["session_id"],
        "expires_at": int(row["expires_at"]),
        "active": bool(row["active"]),
    }
    REFRESH_TOKENS[refresh_token] = record
    return record


def get_active_refresh_token_for_session(username, session_id):
    for refresh_token, record in REFRESH_TOKENS.items():
        if (
            record.get("username") == username
            and record.get("session_id") == session_id
            and record.get("active")
            and now() < int(record.get("expires_at", 0))
        ):
            return refresh_token, record

    with db_connect() as conn:
        row = conn.execute(
            """
            SELECT refresh_token, username, session_id, expires_at, active
            FROM refresh_tokens
            WHERE username = ? AND session_id = ? AND active = 1 AND expires_at > ?
            ORDER BY expires_at DESC
            LIMIT 1
            """,
            (username, session_id, now()),
        ).fetchone()
    if not row:
        return None, None

    record = {
        "username": row["username"],
        "session_id": row["session_id"],
        "expires_at": int(row["expires_at"]),
        "active": bool(row["active"]),
    }
    refresh_token = row["refresh_token"]
    REFRESH_TOKENS[refresh_token] = record
    return refresh_token, record


def set_refresh_token_active(refresh_token, active):
    record = get_refresh_token_record(refresh_token)
    if record:
        record["active"] = bool(active)
    with db_connect() as conn:
        conn.execute("UPDATE refresh_tokens SET active = ? WHERE refresh_token = ?", (1 if active else 0, refresh_token))


def local_timezone():
    if ZoneInfo:
        try:
            return ZoneInfo(LOCAL_TIMEZONE_NAME)
        except Exception:
            pass
    return timezone(timedelta(hours=-3), "America/Sao_Paulo")


def local_time_fields(epoch_seconds):
    try:
        epoch = int(epoch_seconds)
    except (TypeError, ValueError):
        return {"local_time": "", "local_time_iso": "", "timezone": LOCAL_TIMEZONE_NAME}
    dt = datetime.fromtimestamp(epoch, local_timezone())
    return {
        "local_time": dt.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "local_time_iso": dt.isoformat(timespec="seconds"),
        "timezone": LOCAL_TIMEZONE_NAME,
    }


def token_fingerprint(token):
    if not token:
        return ""
    return hashlib.sha256(token.encode()).hexdigest()[:16]


def normalize_supplied_refresh_token(value):
    token = (value or "").strip()
    if token.upper() in {"[REDACTED]", "REDACTED", "NULL", "UNDEFINED", "YOUR_REFRESH_TOKEN"}:
        return ""
    return token


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


def make_refresh_token(username, session_id, expires_at):
    payload = {
        "typ": "refresh",
        "iss": JWT_ISSUER,
        "sub": username,
        "sid": session_id,
        "exp": int(expires_at),
        "jti": str(uuid.uuid4()),
    }
    payload_part = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signature = hmac.new(JWT_SECRET.encode(), payload_part.encode(), hashlib.sha256).digest()
    return f"rt.{payload_part}.{b64url_encode(signature)}"


def verify_portable_refresh_token(refresh_token):
    try:
        prefix, payload_part, signature_part = refresh_token.split(".")
        if prefix != "rt":
            return None
        expected = hmac.new(JWT_SECRET.encode(), payload_part.encode(), hashlib.sha256).digest()
        supplied = b64url_decode(signature_part)
        if not hmac.compare_digest(expected, supplied):
            return None
        payload = json.loads(b64url_decode(payload_part))
        if payload.get("iss") != JWT_ISSUER or payload.get("typ") != "refresh":
            return None
        if now() >= int(payload.get("exp", 0)):
            return None
        username = payload.get("sub", "")
        session_id = payload.get("sid", "")
        if username not in USERS or not session_id:
            return None
        return {
            "username": username,
            "session_id": session_id,
            "expires_at": int(payload["exp"]),
            "active": True,
            "portable": True,
        }
    except Exception:
        return None


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
        session = get_session(payload.get("sid"))
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


def redact_sensitive_xml(value):
    redacted = str(value)
    for tag in SENSITIVE_XML_TAGS:
        redacted = re.sub(
            rf"(<(?:[^>:]+:)?{tag}\b[^>]*>)([\s\S]*?)(</(?:[^>:]+:)?{tag}>)",
            rf"\1[REDACTED]\3",
            redacted,
            flags=re.IGNORECASE,
        )
    return redacted


def fingerprint_header_value(header_name, header_value):
    if not header_value:
        return ""
    name = header_name.lower()
    if name == "authorization" and header_value.startswith("Bearer "):
        return f"Bearer fingerprint:{token_fingerprint(header_value.removeprefix('Bearer ').strip())}"
    if name in SENSITIVE_HEADERS:
        return "[REDACTED]"
    return header_value


def is_login_tracking_event(entry):
    event = str(entry.get("event", ""))
    error = str(entry.get("error", ""))
    path = str(entry.get("path", ""))

    if entry.get("type") == "auth":
        searchable = f"{event} {error}"
        return any(marker in searchable for marker in LOGIN_TRACKING_EVENT_MARKERS)

    if entry.get("type") == "interaction":
        soap_action = str(entry.get("soap_action", ""))
        if path in LOGIN_TRACKING_PATHS:
            return True
        return soap_action in {"Login", "RefreshToken", "ValidateToken"}

    return path in LOGIN_TRACKING_PATHS


def append_audit_event(entry):
    AUDIT_LOG.append(entry)
    if len(AUDIT_LOG) > 5000:
        del AUDIT_LOG[: len(AUDIT_LOG) - 5000]
    try:
        with db_connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (created_at, event_type, client, path, payload)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    int(entry.get("time", now())),
                    str(entry.get("type", "")),
                    str(entry.get("client", "")),
                    str(entry.get("path", "")),
                    json.dumps(entry, ensure_ascii=False),
                ),
            )
    except Exception:
        pass


def persisted_audit_events(limit=5000):
    try:
        with db_connect() as conn:
            rows = conn.execute(
                """
                SELECT payload
                FROM audit_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        events = []
        for row in reversed(rows):
            try:
                events.append(json.loads(row["payload"]))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
        return events
    except Exception:
        return list(AUDIT_LOG[-limit:])


def login_tracking_report(limit=100):
    all_events = persisted_audit_events(max(5000, limit))
    events = [entry for entry in all_events if is_login_tracking_event(entry)]
    selected = []
    for entry in events[-limit:]:
        enriched = dict(entry)
        enriched.update(local_time_fields(entry.get("time")))
        headers = enriched.get("headers")
        if isinstance(headers, dict):
            enriched.setdefault("user_agent", headers.get("User-Agent") or headers.get("user-agent") or "")
            enriched.setdefault("x_forwarded_for", headers.get("X-Forwarded-For") or headers.get("x-forwarded-for") or "")
        if "status" in enriched and isinstance(enriched.get("status"), int):
            enriched.setdefault("http_status", enriched["status"])
        details = enriched.get("details")
        if isinstance(details, dict):
            enriched["details"] = dict(details)
            for key in ("access_token_expires_at", "refresh_token_expires_at", "new_access_token_expires_at"):
                if key in enriched["details"]:
                    enriched["details"][f"{key}_local"] = local_time_fields(enriched["details"][key])["local_time"]
        selected.append(enriched)
    summary = {
        "total_events": len(events),
        "returned_events": len(selected),
        "timezone": LOCAL_TIMEZONE_NAME,
        "login_attempts": 0,
        "login_success": 0,
        "login_failure": 0,
        "refresh_token_requests": 0,
        "refresh_token_success": 0,
        "refresh_token_failure": 0,
        "token_validation_events": 0,
        "expired_session_or_token_events": 0,
        "new_token_events": 0,
    }

    for entry in events:
        event = str(entry.get("event", ""))
        error = str(entry.get("error", ""))
        status = str(entry.get("status", ""))
        details = entry.get("details", {}) if isinstance(entry.get("details", {}), dict) else {}

        if "login" in event:
            summary["login_attempts"] += 1
            if status == "success":
                summary["login_success"] += 1
            if status == "failure":
                summary["login_failure"] += 1

        if "refresh_token" in event:
            summary["refresh_token_requests"] += 1
            if status == "success":
                summary["refresh_token_success"] += 1
            if status == "failure":
                summary["refresh_token_failure"] += 1

        if "validate_token" in event or "access_token_validation" in event:
            summary["token_validation_events"] += 1

        if error in {"token_expired", "session_expired", "session_not_found", "refresh_token_expired"}:
            summary["expired_session_or_token_events"] += 1

        if (
            "access_token_fingerprint" in details
            or "new_access_token_fingerprint" in details
            or "new_refresh_token_fingerprint" in details
        ):
            summary["new_token_events"] += 1

    return {
        "description": "Authentication tracking evidence for login attempts, token validation, expired sessions/tokens, token refresh requests, and new token issuance.",
        "retention": "audit events, sessions, and refresh tokens are stored in SQLite on the active replica",
        "summary": summary,
        "events": selected,
    }


def is_login_audit_event(entry):
    event = str(entry.get("event", ""))
    path = str(entry.get("path", "")).split("?")[0]
    soap_action = str(entry.get("soap_action", ""))

    if entry.get("type") == "auth":
        return event in LOGIN_AUDIT_AUTH_EVENTS or event in {
            "login",
            "refresh_token",
            "rest_login",
            "rest_refresh_token",
        }

    if entry.get("type") == "interaction":
        if path in LOGIN_AUDIT_PATHS:
            if path == "/soap":
                return soap_action == "Logout"
            return True
        return soap_action in {"Login", "RefreshToken", "Logout"}

    return path in LOGIN_AUDIT_PATHS


def login_audit_report(limit=100):
    all_events = persisted_audit_events(max(5000, limit))
    events = [entry for entry in all_events if is_login_audit_event(entry)]
    selected = []
    for entry in events[-limit:]:
        enriched = dict(entry)
        enriched.update(local_time_fields(entry.get("time")))
        headers = enriched.get("headers")
        if isinstance(headers, dict):
            enriched.setdefault("user_agent", headers.get("User-Agent") or headers.get("user-agent") or "")
            enriched.setdefault("x_forwarded_for", headers.get("X-Forwarded-For") or headers.get("x-forwarded-for") or "")
            enriched.setdefault("destination", headers.get("Host") or headers.get("host") or enriched.get("destination", ""))
        if "status" in enriched and isinstance(enriched.get("status"), int):
            enriched.setdefault("http_status", enriched["status"])
        selected.append(enriched)

    summary = {
        "total_events": len(events),
        "returned_events": len(selected),
        "timezone": LOCAL_TIMEZONE_NAME,
        "login_success": 0,
        "login_failure": 0,
        "refresh_success": 0,
        "refresh_failure": 0,
        "logout_success": 0,
        "logout_failure": 0,
    }
    for entry in events:
        event = str(entry.get("event", ""))
        status = str(entry.get("status", ""))
        if "login" in event and "refresh" not in event:
            summary["login_success" if status == "success" else "login_failure"] += 1
        if "refresh" in event:
            summary["refresh_success" if status == "success" else "refresh_failure"] += 1
        if "logout" in event:
            summary["logout_success" if status == "success" else "logout_failure"] += 1

    return {
        "description": "Login audit evidence for login, re-login through refresh token, and logout interactions.",
        "retention": "audit events, sessions, and refresh tokens are stored in SQLite on the active replica",
        "summary": summary,
        "events": selected,
    }


def issue_tokens(username):
    session_id = secrets.token_urlsafe(24)
    user = USERS[username]
    current = now()
    refresh_expires_at = current + REFRESH_TOKEN_TTL_SECONDS
    refresh_token = make_refresh_token(username, session_id, refresh_expires_at)
    save_session(session_id, username, current, current + SESSION_TTL_SECONDS)
    save_refresh_token(refresh_token, username, session_id, refresh_expires_at, True)
    access_token, claims = make_jwt(username, user["role"], session_id)
    return access_token, refresh_token, session_id, claims


def rotate_refresh_token(refresh_token):
    record = get_refresh_token_record(refresh_token)
    if not record:
        return None, "refresh_token_not_found"
    if not record["active"]:
        return None, "refresh_token_reused"
    if now() >= record["expires_at"]:
        return None, "refresh_token_expired"
    session = get_session(record["session_id"])
    if not session or now() >= session["expires_at"]:
        return None, "session_expired"

    set_refresh_token_active(refresh_token, False)
    refresh_expires_at = now() + REFRESH_TOKEN_TTL_SECONDS
    new_refresh_token = make_refresh_token(record["username"], record["session_id"], refresh_expires_at)
    save_refresh_token(new_refresh_token, record["username"], record["session_id"], refresh_expires_at, True)
    save_session(record["session_id"], session["username"], session["created_at"], now() + SESSION_TTL_SECONDS)
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

init_database()


class SoapDastHandler(BaseHTTPRequestHandler):
    server_version = "SoapDastLab/1.0"

    def audit_headers(self):
        return {
            key: fingerprint_header_value(key, value)
            for key, value in self.headers.items()
            if key.lower()
            in {
                "authorization",
                "content-type",
                "soapaction",
                "user-agent",
                "cookie",
                "x-session-token",
                "x-forwarded-for",
                "x-real-ip",
                "forwarded",
                "host",
            }
        }

    def request_tracking_fields(self):
        return {
            "user_agent": self.headers.get("User-Agent", ""),
            "x_forwarded_for": self.headers.get("X-Forwarded-For", ""),
            "x_real_ip": self.headers.get("X-Real-IP", ""),
            "forwarded": self.headers.get("Forwarded", ""),
            "destination": self.headers.get("Host", ""),
        }

    def log_interaction_event(self, event, status=None, action=None, request_body=None, response_body=None, details=None):
        entry = {
            "type": "interaction",
            "time": now(),
            "client": self.client_address[0],
            "method": self.command,
            "path": self.path,
            "event": event,
            "headers": self.audit_headers(),
        }
        entry.update(self.request_tracking_fields())
        if status is not None:
            entry["status"] = status
            entry["http_status"] = status
        if action:
            entry["soap_action"] = action
        if request_body is not None:
            redacted_request_body = redact_sensitive_xml(request_body)
            entry["request_body_length"] = len(request_body)
            entry["raw_request_body"] = request_body
            entry["request_body"] = redacted_request_body
            entry["request_body_preview"] = redacted_request_body[:1000]
        if response_body is not None:
            redacted_response_body = redact_sensitive_xml(response_body)
            entry["response_body_length"] = len(response_body)
            entry["raw_response_body"] = response_body
            entry["response_body"] = redacted_response_body
            entry["response_body_preview"] = redacted_response_body[:1000]
        if details:
            entry["details"] = details
        append_audit_event(entry)

    def log_message(self, fmt, *args):
        append_audit_event(
            {
                "type": "http",
                "time": now(),
                "client": self.client_address[0],
                "method": self.command,
                "path": self.path,
                "message": fmt % args,
                **self.request_tracking_fields(),
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
        entry.update(self.request_tracking_fields())
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
        append_audit_event(entry)

    def send_body(self, status, body, content_type="application/xml", headers=None):
        raw = body.encode("utf-8")
        self.log_interaction_event(
            "response_sent",
            status=status,
            action=getattr(self, "_soap_action", ""),
            response_body=body,
            details={"content_type": content_type, "response_bytes": len(raw)},
        )
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

    def send_head_only(self, status=200, content_type="application/xml", headers=None):
        self.log_interaction_event(
            "response_sent",
            status=status,
            action=getattr(self, "_soap_action", ""),
            details={"content_type": content_type, "response_bytes": 0, "head_only": True},
        )
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", "0")
        self.send_header("X-DAST-Lab", "soap-jwt-refresh-session")
        self.send_header("Cache-Control", "no-store")
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, POST, PUSH, PUT, PATCH, DELETE, OPTIONS, TRACE")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUSH, PUT, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, SOAPAction, X-Session-Token")
        self.send_header("X-DAST-Lab", "verb-discovery")
        self.end_headers()

    def do_TRACE(self):
        self.send_body(405, "TRACE is intentionally rejected by the lab target.\n", "text/plain")

    def do_HEAD(self):
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/health", "/soap", "/soap/auth", "/soap/refreshtoken", "/audit", "/login-tracking", "/login-audit"}:
            self.send_head_only(200)
            return
        if parsed.path == "/soap" and "wsdl" in parse_qs(parsed.query, keep_blank_values=True):
            self.send_head_only(200)
            return
        self.send_head_only(404)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.send_json(200, {"status": "ok", "service": "api-server-test"})
            return
        if parsed.path == "/":
            self.send_json(
                200,
                {
                    "name": "SOAP DAST Lab",
                    "soap": "/soap",
                    "soap_auth": "/soap/auth",
                    "soap_refresh_token": "/soap/refreshtoken",
                    "wsdl": "/soap?wsdl",
                    "verbs": "/verbs",
                    "admin": "/admin",
                    "user": "/user",
                    "products": "/products",
                    "audit": "/audit",
                    "login_tracking": "/login-tracking",
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
                    "soap_auth_endpoint": "/soap/auth",
                    "soap_refresh_token_endpoint": "/soap/refreshtoken",
                    "required_method": "POST",
                    "required_headers": ["Content-Type: text/xml", "SOAPAction: <operation>"],
                    "business_operations": ["GetAccount", "TransferFunds", "SearchUser", "Logout"],
                    "auth_operations": {
                        "/soap/auth": ["Login", "ValidateToken"],
                        "/soap/refreshtoken": ["RefreshToken"],
                    },
                },
            )
            return
        if parsed.path == "/audit":
            self.send_json(200, {"events": AUDIT_LOG[-50:]})
            return
        if parsed.path == "/login-tracking":
            query = parse_qs(parsed.query, keep_blank_values=True)
            try:
                limit = int(query.get("limit", ["100"])[0])
            except ValueError:
                limit = 100
            limit = max(1, min(limit, 500))
            self.send_json(200, login_tracking_report(limit))
            return
        if parsed.path == "/login-audit":
            query = parse_qs(parsed.query, keep_blank_values=True)
            try:
                limit = int(query.get("limit", ["100"])[0])
            except ValueError:
                limit = 100
            limit = max(1, min(limit, 500))
            self.send_json(200, login_audit_report(limit))
            return
        if parsed.path == "/soap/auth":
            self.send_json(
                200,
                {
                    "service": "SOAP DAST Lab Auth",
                    "soap_auth_endpoint": "/soap/auth",
                    "soap_refresh_token_endpoint": "/soap/refreshtoken",
                    "required_method": "POST",
                    "allowed_soap_actions": ["Login", "ValidateToken"],
                    "audit": "Authentication and token validation attempts are recorded in /audit.",
                    "login_tracking": "/login-tracking",
                    "login_audit": "/login-audit",
                },
            )
            return
        if parsed.path == "/soap/refreshtoken":
            self.send_json(
                200,
                {
                    "service": "SOAP DAST Lab Refresh Token",
                    "soap_refresh_token_endpoint": "/soap/refreshtoken",
                    "required_method": "POST",
                    "allowed_soap_actions": ["RefreshToken"],
                    "audit": "Refresh token requests are recorded in /audit and /login-tracking.",
                    "login_tracking": "/login-tracking",
                    "login_audit": "/login-audit",
                },
            )
            return
        if parsed.path == "/verbs":
            self.send_json(200, self.verb_payload("GET"))
            return
        if parsed.path == "/admin":
            self.handle_admin_get()
            return
        if parsed.path == "/user":
            self.handle_user_get()
            return
        if parsed.path == "/products":
            self.handle_products_get()
            return
        self.send_json(404, {"error": "not_found"})

    def do_PUT(self):
        if urlparse(self.path).path == "/products":
            self.handle_product_edit()
            return
        self.handle_verb_probe("PUT")

    def do_PATCH(self):
        if urlparse(self.path).path == "/products":
            self.handle_product_edit()
            return
        self.handle_verb_probe("PATCH")

    def do_PUSH(self):
        parsed = urlparse(self.path)
        if parsed.path == "/products":
            self.handle_product_edit()
            return
        self.send_json(404, {"error": "not_found"})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path == "/products":
            self.handle_product_delete(parsed)
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
                "account": account_summary(payload),
                "capabilities": ["GET /products", "POST /products", "PUSH /products", "DELETE /products"],
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
                "account": account_summary(payload),
                "message": "User role can only use GET. Prices and write operations are hidden.",
            },
        )

    def handle_products_get(self):
        payload, error = self.require_auth()
        if error:
            self.send_json(401, {"error": error})
            return
        if payload.get("role") == "admin":
            products = self.products_for_admin()
        else:
            products = self.products_for_user()
        self.send_json(
            200,
            {
                "path": "/products",
                "authenticated_as": payload.get("sub"),
                "role": payload.get("role"),
                "products": products,
            },
        )

    def read_structured_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
        self.log_interaction_event("request_body_received", request_body=raw_body)
        content_type = self.headers.get("Content-Type", "")
        if "json" in content_type:
            return json.loads(raw_body or "{}")
        if not raw_body.strip():
            return {}
        root = ElementTree.fromstring(raw_body)
        if root.tag.split("}")[-1] == "String" and (root.text or "").strip().startswith("<"):
            scanner_xml = html.unescape(root.text or "").replace("\\r", "\r").replace("\\n", "\n").strip()
            root = ElementTree.fromstring(scanner_xml)
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
                    "message": f"Admins can use {method} on /products.",
                    "allowed_path": "/products",
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
                "path": "/products",
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
                "path": "/products",
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
                "path": "/products",
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
        if parsed.path == "/products":
            override_method = self.headers.get("X-HTTP-Method-Override", "").upper()
            if override_method == "PUSH":
                self.handle_product_edit()
                return
            self.handle_product_create()
            return
        if parsed.path not in {"/soap", "/soap/auth", "/soap/refreshtoken"}:
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
        self._soap_action = action
        self.log_interaction_event("soap_request_received", action=action, request_body=raw_body)
        if parsed.path == "/soap" and action in {"Login", "RefreshToken", "ValidateToken"}:
            required_path = "/soap/refreshtoken" if action == "RefreshToken" else "/soap/auth"
            self.log_auth_event(
                "soap_auth_wrong_route",
                "failure",
                error="auth_route_required",
                details={"soap_action": action, "required_path": required_path},
            )
            self.send_body(400, soap_fault("Client.AuthRouteRequired", f"Use {required_path} for SOAPAction: {action}"))
            return
        if parsed.path == "/soap/auth" and action == "RefreshToken":
            self.log_auth_event(
                "soap_refresh_wrong_route",
                "failure",
                error="refresh_route_required",
                details={"soap_action": action, "required_path": "/soap/refreshtoken"},
            )
            self.send_body(400, soap_fault("Client.RefreshRouteRequired", "Use /soap/refreshtoken for SOAPAction: RefreshToken"))
            return
        if parsed.path == "/soap/auth" and action not in {"Login", "ValidateToken"}:
            self.log_auth_event(
                "soap_auth_route_rejected",
                "failure",
                error="unsupported_auth_action",
                details={"soap_action": action, "allowed_actions": ["Login", "ValidateToken"]},
            )
            self.send_body(400, soap_fault("Client.UnsupportedAuthAction", f"/soap/auth only accepts Login or ValidateToken, got: {action}"))
            return
        if parsed.path == "/soap/refreshtoken" and action != "RefreshToken":
            self.log_auth_event(
                "soap_refresh_route_rejected",
                "failure",
                error="unsupported_refresh_action",
                details={"soap_action": action, "allowed_actions": ["RefreshToken"]},
            )
            self.send_body(400, soap_fault("Client.UnsupportedRefreshAction", f"/soap/refreshtoken only accepts RefreshToken, got: {action}"))
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
        started_at = time.perf_counter()
        username = xml_text(root, "Username")
        password = xml_text(root, "Password")
        user = USERS.get(username)
        if not user or not hmac.compare_digest(user["password"], password):
            self.log_auth_event(
                "login",
                "failure",
                username=username,
                error="invalid_credentials",
                details={"duration_ms": round((time.perf_counter() - started_at) * 1000, 2)},
            )
            self.send_body(401, soap_fault("Auth.InvalidCredentials", "Invalid username or password"))
            return
        access_token, refresh_token, session_id, claims = issue_tokens(username)
        refresh_record = get_refresh_token_record(refresh_token) or {}
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
                "refresh_token_expires_at": refresh_record.get("expires_at"),
                "refresh_token_ttl_seconds": REFRESH_TOKEN_TTL_SECONDS,
                "duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
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
        started_at = time.perf_counter()
        refresh_token = xml_text(root, "RefreshToken")
        old_refresh_fingerprint = token_fingerprint(refresh_token)
        result, error = rotate_refresh_token(refresh_token)
        if error:
            self.log_auth_event(
                "refresh_token",
                "failure",
                error=error,
                details={
                    "refresh_token_fingerprint": old_refresh_fingerprint,
                    "duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
                },
            )
            self.send_body(401, soap_fault("Auth.RefreshFailed", error))
            return
        access_token, new_refresh_token, session_id, claims = result
        refresh_record = get_refresh_token_record(new_refresh_token) or {}
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
                "refresh_token_expires_at": refresh_record.get("expires_at"),
                "refresh_rotated": True,
                "duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
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
        session = get_session(payload["sid"])
        delete_session(payload["sid"])
        if refresh_token:
            set_refresh_token_active(refresh_token, False)
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


# API server entrypoint.
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

        # SecurityNote: accepts unsigned JWTs and does not validate signatures.
        if header.get("alg") == "none":
            return payload, None

        # SecurityNote: for signed-looking tokens, only parses claims and ignores
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
        # SecurityNote: intentionally does not XML-escape reflected values.
        lines.append(f"      <lab:{key}>{value}</lab:{key}>")
    lines.append(f"    </lab:{action}Response>")
    return soap_envelope("\n".join(lines))


LAB_WSDL = WSDL.replace(
    f":{PUBLIC_PORT}/", f":{PUBLIC_PORT}/"
).replace(
    f"://{PUBLIC_HOST}:", f"://{PUBLIC_HOST}:"
).replace(
    "SecurityTestService", "SecurityTestLabService"
)


def public_base_url():
    scheme = os.environ.get("SOAP_DAST_PUBLIC_SCHEME", "http")
    return f"{scheme}://{PUBLIC_HOST}:{PUBLIC_PORT}"


def product_for_admin(sku, product):
    return {"sku": sku, "name": product["name"], "price": product["price"], "stock": product["stock"]}


def product_for_user(sku, product):
    return {"sku": sku, "name": product["name"], "available": product["stock"] > 0}


def account_summary(payload):
    username = payload.get("sub", "")
    user = USERS.get(username, {})
    return {
        "username": username,
        "role": payload.get("role", ""),
        "account_id": user.get("account_id", ""),
        "balance": user.get("balance", 0),
        "session_id": payload.get("sid", ""),
        "token_id": payload.get("jti", ""),
        "token_expires_at": payload.get("exp", 0),
    }


def category_slug_from_path(path, prefix):
    if not path.startswith(prefix):
        return ""
    slug = path[len(prefix):].strip("/")
    return slug if "/" not in slug else ""


def filter_catalog_products(category, query):
    return catalog_products(category, query)


def looks_like_sql_injection(query):
    combined = " ".join(values[0] for values in query.values() if values).lower()
    markers = ["'", "\"", " or ", " union ", "--", ";", "/*", " drop ", " select ", " sleep(", "1=1"]
    return any(marker in combined for marker in markers)


def lab_catalog_sql(category, query):
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


SWAGGER_PRODUCT_CREATE_EXAMPLES = [
    {"sku": "SKU-SWG-001", "name": "Aurora Smart TV 55", "price": 2499.90, "stock": 8},
    {"sku": "SKU-SWG-002", "name": "Boreal Notebook Pro", "price": 5299.90, "stock": 5},
    {"sku": "SKU-SWG-003", "name": "Cosmos Smartphone 5G", "price": 3199.90, "stock": 12},
    {"sku": "SKU-SWG-004", "name": "Delta Wireless Headset", "price": 399.90, "stock": 20},
    {"sku": "SKU-SWG-005", "name": "Equinox Gaming Router", "price": 899.90, "stock": 7},
]


SWAGGER_PRODUCT_UPDATE_EXAMPLES = [
    {"sku": "SKU-SWG-001", "name": "Aurora Smart TV 55", "price": 2299.90, "stock": 8},
    {"sku": "SKU-SWG-002", "name": "Boreal Notebook Pro", "price": 4999.90, "stock": 5},
    {"sku": "SKU-SWG-003", "name": "Cosmos Smartphone 5G", "price": 2899.90, "stock": 12},
    {"sku": "SKU-SWG-004", "name": "Delta Wireless Headset", "price": 349.90, "stock": 20},
    {"sku": "SKU-SWG-005", "name": "Equinox Gaming Router", "price": 799.90, "stock": 7},
]


def named_product_examples(products, summary_prefix):
    return {
        product["sku"].lower(): {
            "summary": f"{summary_prefix} {product['sku']}",
            "value": product,
        }
        for product in products
    }


def product_xml(product):
    return (
        "<product>"
        f"<sku>{product['sku']}</sku>"
        f"<name>{product['name']}</name>"
        f"<price>{product['price']}</price>"
        f"<stock>{product['stock']}</stock>"
        "</product>"
    )


def named_product_xml_examples(products, summary_prefix):
    return {
        product["sku"].lower(): {
            "summary": f"{summary_prefix} {product['sku']}",
            "value": product_xml(product),
        }
        for product in products
    }


def x_forwarded_for_parameter():
    return {
        "name": "X-Forwarded-For",
        "in": "header",
        "required": False,
        "schema": {"type": "string"},
        "example": "203.0.113.10",
        "description": "Optional source IP evidence header captured by /login-audit.",
    }


def rest_openapi_spec():
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "SOAP and REST DAST Lab - REST JSON API",
            "version": "1.0.0",
            "description": "Intentionally testable REST JSON API for authorized DAST/fuzzing demonstrations.",
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
                    "parameters": [x_forwarded_for_parameter()],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/LoginRequest"}}},
                    },
                    "responses": {"200": {"description": "Tokens issued"}, "401": {"description": "Invalid credentials"}},
                }
            },
            "/api/refresh": {
                "post": {
                    "summary": "Issue a new dynamic JWT using a reusable reusable refresh token",
                    "parameters": [x_forwarded_for_parameter()],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/RefreshRequest"}}},
                    },
                    "responses": {"200": {"description": "New JWT issued"}, "401": {"description": "Refresh failed"}},
                }
            },
            "/api/logout": {
                "post": {
                    "summary": "Logout the current REST session and optionally deactivate the supplied refresh token",
                    "security": [{"bearerAuth": []}],
                    "parameters": [x_forwarded_for_parameter()],
                    "requestBody": {
                        "required": False,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/RefreshRequest"},
                                "example": {"refreshToken": "YOUR_REFRESH_TOKEN"},
                            }
                        },
                    },
                    "responses": {"200": {"description": "Logged out"}, "401": {"description": "Token rejected"}},
                }
            },
            "/api/validate": {
                "get": {
                    "summary": "Validate bearer token using intentionally weak JWT validation",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "Token accepted"}, "401": {"description": "Token rejected"}},
                }
            },
            "/api/admin": {
                "get": {
                    "summary": "Admin authenticated account data",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "Admin account data"}, "403": {"description": "Role forbidden"}},
                }
            },
            "/api/user": {
                "get": {
                    "summary": "User authenticated account data",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "User account data"}, "403": {"description": "Role forbidden"}},
                }
            },
            "/api/products": {
                "get": {
                    "summary": "List products. Admin sees prices; user sees availability only",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "Product list"}},
                },
                "post": {
                    "summary": "Admin create product. Use X-HTTP-Method-Override: PUSH as Azure-compatible edit fallback",
                    "security": [{"bearerAuth": []}],
                    "parameters": [{"name": "X-HTTP-Method-Override", "in": "header", "required": False, "schema": {"type": "string", "enum": ["PUSH"]}}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Product"},
                                "examples": {
                                    **named_product_examples(SWAGGER_PRODUCT_CREATE_EXAMPLES, "Create product"),
                                    **{
                                        f"update-{key}": value
                                        for key, value in named_product_examples(
                                            SWAGGER_PRODUCT_UPDATE_EXAMPLES,
                                            "Update price with X-HTTP-Method-Override: PUSH for",
                                        ).items()
                                    },
                                },
                            }
                        },
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
            "/api/products/push": {
                "post": {
                    "summary": "Swagger-friendly alias for custom HTTP PUSH edit",
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Product"},
                                "examples": named_product_examples(SWAGGER_PRODUCT_UPDATE_EXAMPLES, "Update product price"),
                            }
                        },
                    },
                    "responses": {"200": {"description": "Product edited"}},
                }
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
                    "summary": "Submit testable comment",
                    "requestBody": {"required": True, "content": {"application/x-www-form-urlencoded": {"schema": {"type": "object", "properties": {"name": {"type": "string"}, "comment": {"type": "string"}}}}}},
                    "responses": {"200": {"description": "HTML page reflecting stored comment without escaping"}},
                },
            },
            "/api/audit": {"get": {"summary": "Read HTTP/auth audit events", "responses": {"200": {"description": "Audit log"}}}},
            "/api/login-tracking": {"get": {"summary": "Read authentication tracking evidence", "responses": {"200": {"description": "Login and token tracking evidence"}}}},
            "/api/login-audit": {"get": {"summary": "Read focused login, refresh, and logout audit evidence", "responses": {"200": {"description": "Login audit evidence"}}}},
            "/report": {"get": {"summary": "Executive HTML authentication report", "responses": {"200": {"description": "Human-readable login tracking report"}}}},
            "/login-audit": {"get": {"summary": "Executive HTML login audit report", "responses": {"200": {"description": "Human-readable login, refresh, and logout report"}}}},
            "/health": {"get": {"summary": "Container health check", "responses": {"200": {"description": "Application is running"}}}},
        },
    }


def xml_openapi_spec():
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "SOAP and REST DAST Lab - XML/SOAP API",
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
                        },
                        x_forwarded_for_parameter(),
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
                        },
                        x_forwarded_for_parameter(),
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
                        },
                        x_forwarded_for_parameter(),
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "text/xml": {
                                "schema": {"type": "string"},
                                "example": "<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:lab=\"urn:soap-dast-lab\"><soap:Body><lab:RefreshToken>YOUR_REFRESH_TOKEN</lab:RefreshToken></soap:Body></soap:Envelope>",
                            },
                            "application/xml": {"schema": {"type": "string"}},
                        },
                    },
                    "responses": {"200": {"description": "SOAP refresh XML response"}, "400": {"description": "Unsupported refresh action"}, "401": {"description": "SOAP auth fault"}},
                }
            },
            "/admin": {
                "get": {"summary": "XML admin authenticated account data", "security": [{"bearerAuth": []}], "responses": {"200": {"description": "XML response"}, "403": {"description": "Role forbidden"}}}
            },
            "/user": {
                "get": {"summary": "XML user authenticated account data", "security": [{"bearerAuth": []}], "responses": {"200": {"description": "XML response"}, "403": {"description": "Role forbidden"}}}
            },
            "/products": {
                "get": {"summary": "XML product list. Admin sees prices; user sees availability only", "security": [{"bearerAuth": []}], "responses": {"200": {"description": "XML response"}}},
                "post": {
                    "summary": "XML admin create product. Use X-HTTP-Method-Override: PUSH as Azure-compatible edit fallback",
                    "security": [{"bearerAuth": []}],
                    "parameters": [{"name": "X-HTTP-Method-Override", "in": "header", "required": False, "schema": {"type": "string", "enum": ["PUSH"]}}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/xml": {
                                "schema": {"type": "string"},
                                "examples": {
                                    **named_product_xml_examples(SWAGGER_PRODUCT_CREATE_EXAMPLES, "Create product"),
                                    **{
                                        f"update-{key}": value
                                        for key, value in named_product_xml_examples(
                                            SWAGGER_PRODUCT_UPDATE_EXAMPLES,
                                            "Update price with X-HTTP-Method-Override: PUSH for",
                                        ).items()
                                    },
                                },
                            },
                            "text/xml": {
                                "schema": {"type": "string"},
                                "examples": named_product_xml_examples(SWAGGER_PRODUCT_CREATE_EXAMPLES, "Create product"),
                            },
                        },
                    },
                    "responses": {"201": {"description": "XML response"}, "200": {"description": "XML edit response when override is PUSH"}, "403": {"description": "Role forbidden"}},
                },
                "delete": {"summary": "XML admin delete product", "security": [{"bearerAuth": []}], "responses": {"200": {"description": "XML response"}, "403": {"description": "Role forbidden"}}},
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
                "post": {"summary": "Submit testable comment", "responses": {"200": {"description": "HTML response with unescaped stored comment"}}},
            },
            "/audit": {"get": {"summary": "XML audit log", "responses": {"200": {"description": "XML audit events"}}}},
            "/login-tracking": {"get": {"summary": "XML authentication tracking evidence", "responses": {"200": {"description": "Login and token tracking evidence"}}}},
            "/login-audit": {"get": {"summary": "HTML login, refresh, and logout audit report", "responses": {"200": {"description": "Human-readable login audit report"}}}},
            "/report": {"get": {"summary": "Executive HTML authentication report", "responses": {"200": {"description": "Human-readable login tracking report"}}}},
            "/health": {"get": {"summary": "Container health check", "responses": {"200": {"description": "Application is running"}}}},
        },
    }


class ApiServerTestHandler(SoapDastHandler):
    server_version = "ApiServerTestLab/1.0"

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
        self.send_header("X-DAST-Lab", "rest-json")
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
        self.log_interaction_event("request_body_received", request_body=raw_body)
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
        # SecurityNote: TRACE reflects request metadata/body.
        self.send_body(200, "\n".join(reflected), "message/http")

    def do_HEAD(self):
        parsed = urlparse(self.path)
        if parsed.path in {
            "/",
            "/health",
            "/swagger",
            "/swagger/rest.json",
            "/swagger/xml.json",
            "/api",
            "/api/admin",
            "/api/user",
            "/api/products",
            "/api/logout",
            "/api/audit",
            "/api/login-tracking",
            "/api/login-audit",
            "/comments",
            "/report",
            "/login-audit",
            "/audit",
            "/login-tracking",
            "/admin",
            "/user",
            "/products",
            "/soap",
            "/soap/auth",
            "/soap/refreshtoken",
        }:
            content_type = "text/html" if parsed.path in {"/comments", "/report", "/login-audit"} else "application/json"
            if parsed.path in {"/audit", "/login-tracking", "/admin", "/user", "/products", "/soap", "/soap/auth", "/soap/refreshtoken"}:
                content_type = "application/xml"
            self.send_head_only(200, content_type=content_type)
            return
        if parsed.path == "/soap" and "wsdl" in parse_qs(parsed.query, keep_blank_values=True):
            self.send_head_only(200)
            return
        self.send_head_only(404, content_type="application/json")

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.send_json_api(200, {"status": "ok", "service": "api-server-test"})
            return
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
                    "name": "SOAP and REST DAST Lab REST JSON API",
                    "swagger": "/swagger/rest.json",
                    "login": "/api/login",
                    "refresh": "/api/refresh",
                    "validate": "/api/validate",
                    "logout": "/api/logout",
                    "admin": "/api/admin",
                    "user": "/api/user",
                    "products": "/api/products",
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
                    "login_audit": "/login-audit",
                    "executive_report": "/report",
                },
            )
            return
        if parsed.path == "/api/audit":
            self.send_json_api(200, {"events": AUDIT_LOG[-50:]})
            return
        if parsed.path == "/api/login-tracking":
            query = parse_qs(parsed.query, keep_blank_values=True)
            try:
                limit = int(query.get("limit", ["100"])[0])
            except ValueError:
                limit = 100
            limit = max(1, min(limit, 500))
            self.send_json_api(200, login_tracking_report(limit))
            return
        if parsed.path == "/api/login-audit":
            query = parse_qs(parsed.query, keep_blank_values=True)
            try:
                limit = int(query.get("limit", ["100"])[0])
            except ValueError:
                limit = 100
            limit = max(1, min(limit, 500))
            self.send_json_api(200, login_audit_report(limit))
            return
        if parsed.path == "/api/validate":
            self.rest_validate_token()
            return
        if parsed.path == "/api/admin":
            self.rest_admin_account()
            return
        if parsed.path == "/api/user":
            self.rest_user_account()
            return
        if parsed.path == "/api/products":
            self.rest_products_list()
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
        if parsed.path == "/report":
            self.render_login_tracking_report(parsed)
            return
        if parsed.path == "/login-audit":
            self.render_login_audit_report(parsed)
            return
        if parsed.path == "/":
            self.send_json_api(
                200,
                {
                    "name": "SOAP and REST DAST Lab",
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
                    "login_audit": "/login-audit",
                    "executive_report": "/report",
                    "risk_signals": [
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
            self.send_body(200, LAB_WSDL)
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
        if parsed.path == "/api/logout":
            self.rest_logout()
            return
        if parsed.path == "/api/products":
            override_method = self.headers.get("X-HTTP-Method-Override", "").upper()
            if override_method == "PUSH":
                self.rest_admin_product_edit()
                return
            self.rest_admin_product_create()
            return
        if parsed.path == "/api/products/push":
            self.rest_admin_product_edit()
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
            # SecurityNote signal: this deliberately acknowledges dangerous XML features
            # instead of rejecting them before parsing.
            self.send_body(
                200,
                unsafe_response_element(
                    "XmlEntityProbe",
                    {
                        "Status": "doctype_seen",
                        "Note": "Test mode accepted a payload containing DOCTYPE/ENTITY markers.",
                        "Echo": raw_body[:500],
                    },
                ),
            )
            return

        try:
            root = ElementTree.fromstring(raw_body)
        except ElementTree.ParseError as exc:
            # SecurityNote: returns parser detail and reflected body fragment.
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
                "lab_soap_auth_wrong_route",
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
                "lab_soap_refresh_wrong_route",
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
                "lab_soap_auth_route_rejected",
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
                "lab_soap_refresh_route_rejected",
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
        if parsed.path == "/api/products":
            self.rest_admin_product_edit()
            return
        super().do_PUSH()

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/products":
            self.rest_admin_product_delete(parsed)
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
        user = USERS.get(username)
        if not user or user["password"] != password:
            self.log_auth_event(
                "lab_rest_login",
                "failure",
                username=username,
                error="invalid_credentials",
                details={"duration_ms": round((time.perf_counter() - started_at) * 1000, 2)},
            )
            self.send_json_api(401, {"error": "invalid_credentials"})
            return
        access_token, refresh_token, session_id, claims = issue_tokens(username)
        fixed_session = self.headers.get("X-Fixed-Session-Id")
        if fixed_session:
            update_session_id(session_id, fixed_session)
            access_token, claims = make_jwt(username, user["role"], fixed_session)
            session_id = fixed_session
        refresh_record = get_refresh_token_record(refresh_token) or {}
        self.log_auth_event(
            "lab_rest_login",
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
                "refresh_token_expires_at": refresh_record.get("expires_at"),
                "refresh_token_ttl_seconds": REFRESH_TOKEN_TTL_SECONDS,
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
                "testMode": True,
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
        record = get_refresh_token_record(refresh_token)
        if not record:
            self.log_auth_event(
                "lab_rest_refresh_token",
                "failure",
                error="refresh_token_not_found",
                details={
                    "refresh_token_fingerprint": token_fingerprint(refresh_token),
                    "duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
                },
            )
            self.send_json_api(401, {"error": "refresh_token_not_found"})
            return
        if int(time.time()) >= int(record.get("expires_at", 0)):
            self.log_auth_event(
                "lab_rest_refresh_token",
                "failure",
                error="refresh_token_expired",
                username=record.get("username"),
                session_id=record.get("session_id"),
                details={
                    "refresh_token_fingerprint": token_fingerprint(refresh_token),
                    "refresh_token_expires_at": record.get("expires_at"),
                    "duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
                },
            )
            self.send_json_api(401, {"error": "refresh_token_expired"})
            return
        user = USERS[record["username"]]
        access_token, claims = make_jwt(record["username"], user["role"], record["session_id"])
        self.log_auth_event(
            "lab_rest_refresh_token",
            "success",
            username=record["username"],
            role=user["role"],
            session_id=record["session_id"],
            token_id=claims["jti"],
            details={
                "refresh_token_fingerprint": token_fingerprint(refresh_token),
                "new_access_token_fingerprint": token_fingerprint(access_token),
                "new_access_token_expires_at": claims["exp"],
                "refresh_token_expires_at": record.get("expires_at"),
                "refresh_rotated": False,
                "security_note": "refresh_token_reuse_allowed",
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
                "security_note": "refresh token reuse allowed",
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
                "security_note": "signature and session binding may be bypassed",
            },
        )

    def rest_logout(self):
        try:
            data = self.read_json_api_body()
        except json.JSONDecodeError as exc:
            self.send_json_api(400, {"error": "invalid_json", "parser_error": str(exc)})
            return
        refresh_token = str(data.get("refreshToken") or data.get("refresh_token") or "")
        payload, error = self.require_auth()
        if error:
            self.log_auth_event("rest_logout", "failure", error=error)
            self.send_json_api(401, {"error": error})
            return
        session = get_session(payload["sid"])
        delete_session(payload["sid"])
        if refresh_token:
            set_refresh_token_active(refresh_token, False)
        self.log_auth_event(
            "rest_logout",
            "success",
            username=payload.get("sub"),
            role=payload.get("role"),
            session_id=payload.get("sid"),
            token_id=payload.get("jti"),
            details={
                "session_removed": session is not None,
                "refresh_token_fingerprint": token_fingerprint(refresh_token),
            },
        )
        self.send_json_api(
            200,
            {
                "status": "logged_out",
                "sessionRemoved": session is not None,
            },
        )

    def rest_admin_account(self):
        payload, status, error = self.require_rest_role("admin")
        if error:
            self.send_json_api(status, error)
            return
        self.send_json_api(
            200,
            {
                "path": "/api/admin",
                "account": account_summary(payload),
                "capabilities": ["GET /api/products", "POST /api/products", "PUSH /api/products", "DELETE /api/products"],
            },
        )

    def rest_user_account(self):
        payload, status, error = self.require_rest_role("user")
        if error:
            self.send_json_api(status, error)
            return
        self.send_json_api(
            200,
            {
                "path": "/api/user",
                "account": account_summary(payload),
                "message": "User role can only use GET /api/products. Prices and write operations are hidden.",
            },
        )

    def rest_products_list(self):
        payload, error = self.require_auth()
        if error:
            self.send_json_api(401, {"error": error})
            return
        products = (
            [product_for_admin(sku, product) for sku, product in PRODUCTS.items()]
            if payload.get("role") == "admin"
            else [product_for_user(sku, product) for sku, product in PRODUCTS.items()]
        )
        self.send_json_api(
            200,
            {
                "path": "/api/products",
                "authenticatedAs": payload.get("sub"),
                "role": payload.get("role"),
                "products": products,
            },
        )

    def rest_fuzzing_catalog(self, category, parsed):
        query = parse_qs(parsed.query, keep_blank_values=True)
        if not catalog_category_exists(category):
            self.send_json_api(404, {"error": "category_not_found", "category": category})
            return
        injected = looks_like_sql_injection(query)
        products = catalog_products(category, query, return_all=injected)
        self.send_json_api(
            200,
            {
                "path": parsed.path,
                "category": category,
                "storage": "sqlite",
                "database": DB_PATH,
                "count": len(products),
                "products": products,
                "query": {key: values[0] if values else "" for key, values in query.items()},
                "labSql": lab_catalog_sql(category, query),
                "sqlInjectionAccepted": injected,
                "warning": "Intentional lab behavior: query parameters are concatenated into a simulated SQL statement.",
            },
        )

    def xml_fuzzing_catalog(self, category, parsed):
        query = parse_qs(parsed.query, keep_blank_values=True)
        if not catalog_category_exists(category):
            self.send_body(404, xml_document("response", {"error": "category_not_found", "category": category}))
            return
        injected = looks_like_sql_injection(query)
        products = catalog_products(category, query, return_all=injected)
        self.send_body(
            200,
            xml_document(
                "response",
                {
                    "path": parsed.path,
                    "category": category,
                    "storage": "sqlite",
                    "database": DB_PATH,
                    "count": len(products),
                    "products": products,
                    "query": {key: values[0] if values else "" for key, values in query.items()},
                    "labSql": lab_catalog_sql(category, query),
                    "sqlInjectionAccepted": injected,
                    "warning": "Intentional lab behavior: query parameters are concatenated into a simulated SQL statement.",
                },
            ),
        )

    def rest_ecommerce_records(self, route_type, parsed):
        query = parse_qs(parsed.query, keep_blank_values=True)
        if not ecommerce_route_exists(route_type):
            self.send_json_api(404, {"error": "ecommerce_route_not_found", "route": route_type})
            return
        records = ecommerce_records(route_type, query)
        self.send_json_api(
            200,
            {
                "path": parsed.path,
                "route": route_type,
                "storage": "sqlite",
                "database": DB_PATH,
                "count": len(records),
                "records": records,
                "query": {key: values[0] if values else "" for key, values in query.items()},
            },
        )

    def xml_ecommerce_records(self, route_type, parsed):
        query = parse_qs(parsed.query, keep_blank_values=True)
        if not ecommerce_route_exists(route_type):
            self.send_body(404, xml_document("response", {"error": "ecommerce_route_not_found", "route": route_type}))
            return
        records = ecommerce_records(route_type, query)
        self.send_body(
            200,
            xml_document(
                "response",
                {
                    "path": parsed.path,
                    "route": route_type,
                    "storage": "sqlite",
                    "database": DB_PATH,
                    "count": len(records),
                    "records": records,
                    "query": {key: values[0] if values else "" for key, values in query.items()},
                },
            ),
        )

    def render_login_tracking_report(self, parsed):
        query = parse_qs(parsed.query, keep_blank_values=True)
        try:
            limit = int(query.get("limit", ["100"])[0])
        except ValueError:
            limit = 100
        limit = max(1, min(limit, 500))
        report = login_tracking_report(limit)
        summary = report["summary"]
        events = report["events"]

        def esc(value):
            return html.escape("" if value is None else str(value), quote=True)

        def status_class(event):
            status = str(event.get("status", "")).lower()
            http_status = int(event.get("http_status") or 0)
            if status == "success" or 200 <= http_status < 300:
                return "ok"
            if status == "failure" or http_status >= 400:
                return "bad"
            return "warn"

        def business_label(event):
            name = str(event.get("event", ""))
            labels = {
                "lab_login": "Login",
                "lab_refresh_token": "Refresh token",
                "lab_validate_token": "Token validation",
                "lab_access_token_validation": "Route access",
                "soap_request_received": "SOAP request",
                "response_sent": "Response",
            }
            return labels.get(name, name.replace("_", " ").title())

        def detail_text(event):
            details = event.get("details")
            if not isinstance(details, dict):
                return ""
            interesting = []
            for key in (
                "duration_ms",
                "refresh_token_source",
                "security_note",
                "refresh_rotated",
                "access_token_ttl_seconds",
                "refresh_token_ttl_seconds",
            ):
                if key in details:
                    interesting.append(f"{key}: {details[key]}")
            return "; ".join(interesting)

        cards = [
            ("Total events", summary["total_events"]),
            ("Login success", summary["login_success"]),
            ("Login failures", summary["login_failure"]),
            ("Refresh requests", summary["refresh_token_requests"]),
            ("Refresh failures", summary["refresh_token_failure"]),
            ("Expired token/session", summary["expired_session_or_token_events"]),
        ]
        card_html = "\n".join(
            f"<section class=\"metric\"><span>{esc(label)}</span><strong>{esc(value)}</strong></section>"
            for label, value in cards
        )
        rows = []
        for event in reversed(events):
            css = status_class(event)
            request_body = event.get("request_body", event.get("request_body_preview", ""))
            response_body = event.get("response_body", event.get("response_body_preview", ""))
            if not request_body and int(event.get("request_body_length") or 0) == 0:
                request_body = "[no request body captured]"
            if not response_body and int(event.get("response_body_length") or 0) == 0:
                response_body = "[no response body captured]"
            rows.append(
                "<tr>"
                f"<td><span class=\"pill {css}\">{esc(event.get('status') or event.get('http_status') or 'observed')}</span></td>"
                f"<td>{esc(event.get('local_time'))}</td>"
                f"<td>{esc(business_label(event))}</td>"
                f"<td>{esc(event.get('username', ''))}</td>"
                f"<td>{esc(event.get('role', ''))}</td>"
                f"<td>{esc(event.get('http_status', ''))}</td>"
                f"<td>{esc(event.get('method', ''))} {esc(event.get('path', ''))}</td>"
                f"<td>{esc(event.get('client', ''))}</td>"
                f"<td>{esc(event.get('x_forwarded_for', ''))}</td>"
                f"<td class=\"ua\">{esc(event.get('user_agent', ''))}</td>"
                f"<td>{esc(event.get('error', ''))}</td>"
                f"<td class=\"details\">{esc(detail_text(event))}</td>"
                f"<td class=\"body-preview\"><pre>{esc(request_body)}</pre></td>"
                f"<td class=\"body-preview\"><pre>{esc(response_body)}</pre></td>"
                "</tr>"
            )
        rows_html = "\n".join(rows) or "<tr><td colspan=\"14\">No authentication events have been recorded yet.</td></tr>"
        recommendation = "Authentication activity is being captured and can be reviewed by business event, result, source IP, forwarded IP, and client user-agent."
        if summary["login_failure"] or summary["refresh_token_failure"]:
            recommendation = "Review failed authentication and refresh attempts first. They may indicate scanner payload issues, expired credentials, or abuse attempts."
        generated_at = local_time_fields(now())["local_time"]
        page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Authentication Executive Report</title>
  <style>
    :root {{ --ink:#17202a; --muted:#617080; --line:#d8dee6; --ok:#137333; --bad:#b3261e; --warn:#8a5a00; --bg:#f6f8fb; }}
    body {{ margin:0; font-family: Arial, Helvetica, sans-serif; color:var(--ink); background:var(--bg); }}
    header {{ background:#fff; border-bottom:1px solid var(--line); padding:24px 32px; }}
    main {{ padding:24px 32px 40px; }}
    h1 {{ margin:0 0 8px; font-size:28px; letter-spacing:0; }}
    h2 {{ margin:28px 0 12px; font-size:20px; }}
    p {{ margin:6px 0; color:var(--muted); }}
    .metrics {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(150px, 1fr)); gap:12px; margin-top:18px; }}
    .metric {{ background:#fff; border:1px solid var(--line); border-radius:8px; padding:14px; }}
    .metric span {{ display:block; color:var(--muted); font-size:13px; }}
    .metric strong {{ display:block; font-size:26px; margin-top:6px; }}
    .note {{ background:#fff; border-left:4px solid #2b6cb0; padding:14px 16px; margin:18px 0; }}
    .toolbar {{ display:flex; gap:10px; align-items:center; margin:18px 0; flex-wrap:wrap; }}
    .toolbar a {{ color:#0645ad; text-decoration:none; font-weight:700; }}
    .table-wrap {{ overflow:auto; max-height:72vh; border:1px solid var(--line); }}
    table {{ min-width:2600px; width:max-content; border-collapse:collapse; background:#fff; table-layout:auto; }}
    th, td {{ border-bottom:1px solid var(--line); padding:10px; text-align:left; vertical-align:top; font-size:13px; overflow-wrap:normal; }}
    th {{ background:#eef2f7; color:#334155; position:sticky; top:0; }}
    th:nth-child(14), th:nth-child(15), td:nth-child(14), td:nth-child(15) {{ width:760px; min-width:760px; }}
    .pill {{ display:inline-block; border-radius:999px; padding:4px 8px; color:#fff; font-size:12px; font-weight:700; }}
    .pill.ok {{ background:var(--ok); }}
    .pill.bad {{ background:var(--bad); }}
    .pill.warn {{ background:var(--warn); }}
    .ua, .details {{ color:#3d4b5c; font-size:12px; }}
    .body-preview pre {{ margin:0; max-height:420px; min-width:340px; overflow:auto; white-space:pre-wrap; font-family: Consolas, Monaco, monospace; font-size:12px; line-height:1.35; color:#2d3748; }}
  </style>
</head>
<body>
  <header>
    <h1>Authentication Executive Report</h1>
    <p>Friendly view generated from <code>/login-tracking</code>. Generated at {esc(generated_at)}.</p>
  </header>
  <main>
    <section class="metrics">{card_html}</section>
    <section class="note"><strong>Executive reading:</strong> {esc(recommendation)}</section>
    <div class="toolbar">
      <span>Showing the latest {esc(summary["returned_events"])} of {esc(summary["total_events"])} tracked events.</span>
      <a href="/login-tracking?limit={limit}">Technical XML</a>
      <a href="/api/login-tracking?limit={limit}">Technical JSON</a>
      <a href="/report?limit=250">Show 250</a>
    </div>
    <h2>Event Timeline</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Result</th><th>Local time</th><th>Business event</th><th>User</th><th>Role</th><th>HTTP</th><th>Route</th><th>Client IP</th><th>X-Forwarded-For</th><th>User-Agent</th><th>Error</th><th>Notes</th><th>Request Body</th><th>Response Body</th>
          </tr>
        </thead>
        <tbody>{rows_html}</tbody>
      </table>
    </div>
  </main>
</body>
</html>"""
        self.send_html(200, page, headers={"X-Report-Source": "/login-tracking"})

    def render_login_audit_report(self, parsed):
        query = parse_qs(parsed.query, keep_blank_values=True)
        try:
            limit = int(query.get("limit", ["100"])[0])
        except ValueError:
            limit = 100
        limit = max(1, min(limit, 500))
        report = login_audit_report(limit)
        summary = report["summary"]
        events = report["events"]

        def esc(value):
            return html.escape("" if value is None else str(value), quote=True)

        def status_class(event):
            status = str(event.get("status", "")).lower()
            http_status = int(event.get("http_status") or 0)
            if status == "success" or 200 <= http_status < 300:
                return "ok"
            if status == "failure" or http_status >= 400:
                return "bad"
            return "warn"

        def business_label(event):
            name = str(event.get("event", ""))
            labels = {
                "lab_login": "Login",
                "lab_rest_login": "REST login",
                "lab_refresh_token": "Re-login refresh token",
                "lab_rest_refresh_token": "REST re-login refresh token",
                "logout": "Logout",
                "rest_logout": "REST logout",
                "soap_request_received": "SOAP request",
                "request_body_received": "REST request",
                "response_sent": "Response",
            }
            return labels.get(name, name.replace("_", " ").title())

        def detail_text(event):
            details = event.get("details")
            if not isinstance(details, dict):
                return ""
            interesting = []
            for key in (
                "duration_ms",
                "refresh_token_source",
                "access_token_fingerprint",
                "refresh_token_fingerprint",
                "new_access_token_fingerprint",
                "refresh_rotated",
                "access_token_ttl_seconds",
                "refresh_token_ttl_seconds",
                "security_note",
                "risk_signal",
                "test_mode",
            ):
                if key in details:
                    interesting.append(f"{key}: {details[key]}")
            return "; ".join(interesting)

        cards = [
            ("Login success", summary["login_success"]),
            ("Login failures", summary["login_failure"]),
            ("Refresh success", summary["refresh_success"]),
            ("Refresh failures", summary["refresh_failure"]),
            ("Logout success", summary["logout_success"]),
            ("Logout failures", summary["logout_failure"]),
        ]
        card_html = "\n".join(
            f"<section class=\"metric\"><span>{esc(label)}</span><strong>{esc(value)}</strong></section>"
            for label, value in cards
        )
        rows = []
        for event in reversed(events):
            css = status_class(event)
            request_body = event.get("raw_request_body") or event.get("request_body") or event.get("request_body_preview", "")
            response_body = event.get("raw_response_body") or event.get("response_body") or event.get("response_body_preview", "")
            if not request_body and int(event.get("request_body_length") or 0) == 0:
                request_body = "[no request body captured]"
            if not response_body and int(event.get("response_body_length") or 0) == 0:
                response_body = "[no response body captured]"
            rows.append(
                "<tr>"
                f"<td><span class=\"pill {css}\">{esc(event.get('status') or event.get('http_status') or 'observed')}</span></td>"
                f"<td>{esc(event.get('local_time'))}</td>"
                f"<td>{esc(business_label(event))}</td>"
                f"<td>{esc(event.get('username', ''))}</td>"
                f"<td>{esc(event.get('role', ''))}</td>"
                f"<td>{esc(event.get('http_status', ''))}</td>"
                f"<td>{esc(event.get('method', ''))} {esc(event.get('path', ''))}</td>"
                f"<td>{esc(event.get('client', ''))}</td>"
                f"<td>{esc(event.get('destination', ''))}</td>"
                f"<td>{esc(event.get('x_forwarded_for', ''))}</td>"
                f"<td class=\"ua\">{esc(event.get('user_agent', ''))}</td>"
                f"<td>{esc(event.get('error', ''))}</td>"
                f"<td class=\"details\">{esc(detail_text(event))}</td>"
                f"<td class=\"body-preview\"><pre>{esc(request_body)}</pre></td>"
                f"<td class=\"body-preview\"><pre>{esc(response_body)}</pre></td>"
                "</tr>"
            )
        rows_html = "\n".join(rows) or "<tr><td colspan=\"15\">No login audit events have been recorded yet.</td></tr>"
        generated_at = local_time_fields(now())["local_time"]
        page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Login Audit Report</title>
  <style>
    :root {{ --ink:#17202a; --muted:#617080; --line:#d8dee6; --ok:#137333; --bad:#b3261e; --warn:#8a5a00; --bg:#f6f8fb; }}
    body {{ margin:0; font-family: Arial, Helvetica, sans-serif; color:var(--ink); background:var(--bg); }}
    header {{ background:#fff; border-bottom:1px solid var(--line); padding:24px 32px; }}
    main {{ padding:24px 32px 40px; }}
    h1 {{ margin:0 0 8px; font-size:28px; letter-spacing:0; }}
    h2 {{ margin:28px 0 12px; font-size:20px; }}
    p {{ margin:6px 0; color:var(--muted); }}
    .metrics {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(150px, 1fr)); gap:12px; margin-top:18px; }}
    .metric {{ background:#fff; border:1px solid var(--line); border-radius:8px; padding:14px; }}
    .metric span {{ display:block; color:var(--muted); font-size:13px; }}
    .metric strong {{ display:block; font-size:26px; margin-top:6px; }}
    .note {{ background:#fff; border-left:4px solid #2b6cb0; padding:14px 16px; margin:18px 0; }}
    .toolbar {{ display:flex; gap:10px; align-items:center; margin:18px 0; flex-wrap:wrap; }}
    .toolbar a {{ color:#0645ad; text-decoration:none; font-weight:700; }}
    .table-wrap {{ overflow:auto; max-height:72vh; border:1px solid var(--line); }}
    table {{ min-width:3000px; width:max-content; border-collapse:collapse; background:#fff; table-layout:auto; }}
    th, td {{ border-bottom:1px solid var(--line); padding:10px; text-align:left; vertical-align:top; font-size:13px; overflow-wrap:normal; }}
    th {{ background:#eef2f7; color:#334155; position:sticky; top:0; }}
    th:nth-child(14), th:nth-child(15), td:nth-child(14), td:nth-child(15) {{ width:900px; min-width:900px; }}
    .pill {{ display:inline-block; border-radius:999px; padding:4px 8px; color:#fff; font-size:12px; font-weight:700; }}
    .pill.ok {{ background:var(--ok); }}
    .pill.bad {{ background:var(--bad); }}
    .pill.warn {{ background:var(--warn); }}
    .ua, .details {{ color:#3d4b5c; font-size:12px; }}
    .body-preview pre {{ margin:0; max-height:560px; width:880px; overflow:auto; white-space:pre; font-family: Consolas, Monaco, monospace; font-size:12px; line-height:1.35; color:#2d3748; }}
  </style>
</head>
<body>
  <header>
    <h1>Login Audit Report</h1>
    <p>Focused view for login, re-login through refresh token, and logout. Generated at {esc(generated_at)}.</p>
  </header>
  <main>
    <section class="metrics">{card_html}</section>
    <section class="note"><strong>Audit scope:</strong> request and response bodies are shown in full for login evidence, including username/password test payloads, JWT access tokens, and refresh tokens.</section>
    <div class="toolbar">
      <span>Showing the latest {esc(summary["returned_events"])} of {esc(summary["total_events"])} matching events.</span>
      <a href="/api/login-audit?limit={limit}">Technical JSON</a>
      <a href="/login-audit?limit=250">Show 250</a>
      <a href="/report?limit={limit}">Full report</a>
    </div>
    <h2>Login Timeline</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Result</th><th>Local time</th><th>Event</th><th>User</th><th>Role</th><th>HTTP</th><th>Route</th><th>Source IP</th><th>Destination</th><th>X-Forwarded-For</th><th>User-Agent</th><th>Error</th><th>Notes</th><th>Request Body</th><th>Response Body</th>
          </tr>
        </thead>
        <tbody>{rows_html}</tbody>
      </table>
    </div>
  </main>
</body>
</html>"""
        self.send_html(200, page, headers={"X-Report-Source": "/login-audit"})

    def render_comments_form(self, parsed):
        query = parse_qs(parsed.query, keep_blank_values=True)
        reflected = query.get("preview", [""])[0]
        comments = "\n".join(
            f"<article class=\"comment\"><strong>{item['name']}</strong><p>{item['comment']}</p></article>"
            for item in recent_comments(25)
        )
        html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Comment Lab</title>
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
  <h1>Comment Lab</h1>
  <nav>
    <a href="/products/eletronico?q=camera">eletronico</a> |
    <a href="/products/smarphone?q=5G">smarphone</a> |
    <a href="/products/laptops?promotion=yes">laptops</a> |
    <a href="/products/books?q=SQL">books</a>
  </nav>
  <p>This page is intentionally testable to stored and reflected XSS for authorized DAST testing.</p>
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
        add_comment(name, comment)
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
        if sku in PRODUCTS:
            self.send_json_api(409, {"error": "product_already_exists", "sku": sku})
            return
        PRODUCTS[sku] = {"name": name, "price": round(price, 2), "stock": stock}
        self.send_json_api(201, {"createdBy": payload.get("sub"), "product": product_for_admin(sku, PRODUCTS[sku])})

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
        if sku not in PRODUCTS:
            self.send_json_api(404, {"error": "product_not_found", "sku": sku})
            return
        before = product_for_admin(sku, PRODUCTS[sku])
        if "name" in data:
            PRODUCTS[sku]["name"] = str(data["name"])
        if "price" in data:
            PRODUCTS[sku]["price"] = round(float(data["price"]), 2)
        if "stock" in data:
            PRODUCTS[sku]["stock"] = int(data["stock"])
        self.send_json_api(
            200,
            {
                "method": self.command,
                "updatedBy": payload.get("sub"),
                "before": before,
                "after": product_for_admin(sku, PRODUCTS[sku]),
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
        if sku not in PRODUCTS:
            self.send_json_api(404, {"error": "product_not_found", "sku": sku})
            return
        deleted = PRODUCTS.pop(sku)
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
            self.log_auth_event("lab_access_token_missing", "failure", error="missing_bearer_token")
            return None, "missing_bearer_token"
        payload, error = insecure_verify_jwt(token)
        if error:
            self.log_auth_event(
                "lab_access_token_validation",
                "failure",
                error=error,
                details={"access_token_fingerprint": token_fingerprint(token)},
            )
            return None, error
        # SecurityNote: cookie/session binding is not enforced.
        self.log_auth_event(
            "lab_access_token_validation",
            "success",
            username=payload.get("sub"),
            role=payload.get("role"),
            session_id=payload.get("sid"),
            token_id=payload.get("jti"),
            details={
                "access_token_fingerprint": token_fingerprint(token),
                "signature_verified": False,
                "session_cookie_enforced": False,
            },
        )
        return payload, None

    def soap_login(self, root):
        started_at = time.perf_counter()
        username = xml_text(root, "Username")
        password = xml_text(root, "Password")
        user = USERS.get(username)
        if not user or user["password"] != password:
            self.log_auth_event(
                "lab_login",
                "failure",
                username=username,
                error="invalid_credentials",
                details={"duration_ms": round((time.perf_counter() - started_at) * 1000, 2)},
            )
            self.send_body(401, soap_fault("Auth.InvalidCredentials", "Invalid username or password"))
            return

        access_token, refresh_token, session_id, claims = issue_tokens(username)
        fixed_session = self.headers.get("X-Fixed-Session-Id")
        if fixed_session:
            # SecurityNote: session fixation through attacker-supplied session id.
            update_session_id(session_id, fixed_session)
            access_token, claims = make_jwt(username, user["role"], fixed_session)
            session_id = fixed_session
        refresh_record = get_refresh_token_record(refresh_token) or {}
        self.log_auth_event(
            "lab_login",
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
                "refresh_token_expires_at": refresh_record.get("expires_at"),
                "refresh_token_ttl_seconds": REFRESH_TOKEN_TTL_SECONDS,
                "session_fixation_used": bool(fixed_session),
                "cookie_security_attributes": "missing_httponly_samesite",
                "duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
            },
        )

        headers = {
            # SecurityNote: intentionally omits HttpOnly/SameSite attributes.
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
                    "TestMode": "true",
                },
            ),
            headers=headers,
        )

    def soap_refresh_token(self, root):
        started_at = time.perf_counter()
        refresh_token = normalize_supplied_refresh_token(xml_text(root, "RefreshToken"))
        refresh_token_source = "soap_body"
        if not refresh_token.strip():
            wrapped_string = normalize_supplied_refresh_token(xml_text(root, "String"))
            if wrapped_string:
                refresh_token = wrapped_string
                refresh_token_source = "wrapped_string_body"
            else:
                refresh_token_source = "missing_or_redacted_soap_body"
        record = get_refresh_token_record(refresh_token)
        if not record and refresh_token.count(".") == 2:
            payload, body_token_error = insecure_verify_jwt(refresh_token)
            if payload:
                fallback_token, fallback_record = get_active_refresh_token_for_session(
                    payload.get("sub", ""),
                    payload.get("sid", ""),
                )
                if fallback_token and fallback_record:
                    refresh_token = fallback_token
                    record = fallback_record
                    refresh_token_source = "access_token_in_refresh_body_fallback"
            else:
                refresh_token_source = f"invalid_body_jwt_{body_token_error}"
        if not record:
            bearer = self.bearer_token()
            if bearer:
                payload, bearer_error = insecure_verify_jwt(bearer)
                if payload:
                    fallback_token, fallback_record = get_active_refresh_token_for_session(
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
            session_id = self.session_cookie()
            session = get_session(session_id) if session_id else None
            if session:
                fallback_token, fallback_record = get_active_refresh_token_for_session(
                    session.get("username", ""),
                    session_id,
                )
                if fallback_token and fallback_record:
                        refresh_token = fallback_token
                        record = fallback_record
                        refresh_token_source = "session_cookie_fallback"
        if not record:
            for entry in reversed(persisted_audit_events(1000)):
                if entry.get("type") != "auth":
                    continue
                if entry.get("client") != self.client_address[0]:
                    continue
                if entry.get("status") != "success":
                    continue
                if entry.get("event") not in {"lab_login", "login"}:
                    continue
                if now() - int(entry.get("time", 0)) > 900:
                    continue
                fallback_token, fallback_record = get_active_refresh_token_for_session(
                    entry.get("username", ""),
                    entry.get("session_id", ""),
                )
                if fallback_token and fallback_record:
                    refresh_token = fallback_token
                    record = fallback_record
                    refresh_token_source = "recent_client_login_fallback"
                    break
        if not record:
            self.log_auth_event(
                "lab_refresh_token",
                "failure",
                error="refresh_token_not_found",
                details={
                    "refresh_token_fingerprint": token_fingerprint(refresh_token),
                    "refresh_token_source": refresh_token_source,
                    "body_refresh_token_present": bool(refresh_token.strip()),
                    "duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
                },
            )
            self.send_body(401, soap_fault("Auth.RefreshFailed", "refresh_token_not_found"))
            return
        if int(time.time()) >= int(record.get("expires_at", 0)):
            self.log_auth_event(
                "lab_refresh_token",
                "failure",
                error="refresh_token_expired",
                username=record.get("username"),
                session_id=record.get("session_id"),
                details={
                    "refresh_token_fingerprint": token_fingerprint(refresh_token),
                    "refresh_token_source": refresh_token_source,
                    "refresh_token_expires_at": record.get("expires_at"),
                    "duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
                },
            )
            self.send_body(401, soap_fault("Auth.RefreshFailed", "refresh_token_expired"))
            return

        # SecurityNote: refresh token is reusable and not rotated.
        user = USERS[record["username"]]
        access_token, claims = make_jwt(record["username"], user["role"], record["session_id"])
        self.log_auth_event(
            "lab_refresh_token",
            "success",
            username=record["username"],
            role=user["role"],
            session_id=record["session_id"],
            token_id=claims["jti"],
            details={
                "refresh_token_fingerprint": token_fingerprint(refresh_token),
                "refresh_token_source": refresh_token_source,
                "new_access_token_fingerprint": token_fingerprint(access_token),
                "new_access_token_expires_at": claims["exp"],
                "refresh_token_expires_at": record.get("expires_at"),
                "refresh_rotated": False,
                "security_note": "refresh_token_reuse_allowed",
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
                    "SecurityNote": "refresh token reuse allowed",
                },
            ),
        )

    def soap_validate_token(self, root):
        payload, error = self.require_auth()
        if error:
            self.log_auth_event("lab_validate_token", "failure", error=error)
            self.send_body(401, soap_fault("Auth.TokenInvalid", error))
            return
        self.log_auth_event(
            "lab_validate_token",
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
                    "SecurityNote": "signature and session binding may be bypassed",
                },
            ),
        )

    def soap_get_account(self, root):
        payload, error = self.require_auth()
        if error:
            self.send_body(401, soap_fault("Auth.Required", error))
            return
        requested_account = xml_text(root, "AccountId") or "1001"
        owner = next(
            (name for name, user in USERS.items() if user["account_id"] == requested_account),
            payload.get("sub", "unknown"),
        )
        balance = USERS.get(owner, {}).get("balance", "unknown")
        # SecurityNote: IDOR. Any authenticated caller can request any account id.
        self.send_body(
            200,
            unsafe_response_element(
                "GetAccount",
                {
                    "AccountId": requested_account,
                    "Owner": owner,
                    "Balance": balance,
                    "RequestedBy": payload.get("sub", ""),
                    "SecurityNote": "idor_account_access",
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
            unsafe_response_element(
                "SearchUser",
                {
                    "Query": query,
                    "Matches": ",".join(matches),
                    "FuzzEcho": query,
                    "SecurityNote": "unsafe_reflection_without_xml_escape",
                },
            ),
        )


def main():
    httpd = ThreadingHTTPServer((HOST, PORT), ApiServerTestHandler)
    print(f"API Server Test running at http://{HOST}:{PORT}")
    print(f"WSDL available at http://{HOST}:{PORT}/soap?wsdl")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
