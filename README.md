# Vulnerable SOAP and REST DAST Lab

## English

### Purpose

This repository is an intentionally vulnerable security lab for demonstrating attacks against SOAP/XML APIs and REST/JSON APIs in an authorized environment.

The application runs on one port:

```text
http://127.0.0.1:8089
```

It exposes two API styles:

- REST API with JSON under `/api`
- SOAP/XML API under `/soap`
- Dedicated SOAP login and token validation route under `/soap/auth`
- Dedicated SOAP refresh token route under `/soap/refreshtoken`

Swagger/OpenAPI documents:

- REST API Swagger: `http://127.0.0.1:8089/swagger/rest.json`
- SOAP/XML Swagger-style document: `http://127.0.0.1:8089/swagger/xml.json`
- WSDL: `http://127.0.0.1:8089/soap?wsdl`

Static OpenAPI files for import:

- `openapi/rest-openapi.json`
- `openapi/soap-openapi.json`

Relational storage:

- The lab uses SQLite by default at `/tmp/rest_soap_labs.db`.
- Override the path with `SOAP_DAST_DB_PATH`.
- Product catalog records, e-commerce records, and XSS comments are stored in relational tables.

DAST authentication scripts and validation helpers:

- `scripts/dast/SRM_Soap.js`
- `scripts/dast/SRM_Rest.js`
- `scripts/dast/test-soap-auth-route.js`
- `scripts/dast/test-rest-auth-route.js`

### Intentional Vulnerabilities

This lab is vulnerable on purpose:

- JWT `alg=none` acceptance
- JWT signature bypass
- Refresh token reuse
- Session fixation with `X-Fixed-Session-Id`
- Missing secure cookie attributes in vulnerable mode
- IDOR on account access
- Unsafe XML reflection
- `DOCTYPE` / `ENTITY` acceptance signal
- TRACE reflection
- Weak session binding
- Full interaction audit for HTTP/SOAP requests, responses, login, token validation, and refresh token use
- Dedicated login tracking evidence at `/login-tracking`
- Executive authentication report at `/report`

Run this only in environments you own or are authorized to test.

### Files

- `server.py`: shared users, token helpers, XML helpers, products, and base handlers
- `vulnerable_server.py`: vulnerable REST/JSON and SOAP/XML application
- `run_both.py`: starts the app selected by `APP_MODE`
- `Dockerfile`: container image
- `docker-compose.yml`: local vulnerable app on port `8089`
- `requests.http`: SOAP examples
- `vulnerable-requests.http`: vulnerable SOAP examples
- `admin-user-requests.http`: XML product route examples
- `rest-json-requests.http`: REST JSON examples
- `openapi/rest-openapi.json`: static OpenAPI file for REST JSON import
- `openapi/soap-openapi.json`: static OpenAPI-style file for SOAP/XML import
- `deploy/aws/`: AWS ECS/Fargate examples
- `deploy/azure/`: Azure Container Apps examples

### Users

Admin users:

| Username | Password |
| --- | --- |
| `admin_aurora` | `adminpass1` |
| `admin_boreal` | `adminpass2` |
| `admin_cosmos` | `adminpass3` |
| `admin_delta` | `adminpass4` |
| `admin_equinox` | `adminpass5` |

Normal users:

| Username | Password |
| --- | --- |
| `user_apollo` | `userpass1` |
| `user_bianca` | `userpass2` |
| `user_cairo` | `userpass3` |
| `user_diana` | `userpass4` |
| `user_elias` | `userpass5` |

### Run Locally With Docker

Build and start:

```bash
docker compose up --build -d
```

Check the container:

```bash
docker compose ps
```

View logs:

```bash
docker compose logs -f
```

Stop:

```bash
docker compose down
```

Health-style checks:

```bash
curl -i 'http://127.0.0.1:8089/api'
curl -i 'http://127.0.0.1:8089/soap?wsdl'
curl -i 'http://127.0.0.1:8089/swagger/rest.json'
curl -i 'http://127.0.0.1:8089/swagger/xml.json'
```

## REST API Interactions

The REST API uses JSON request and response bodies.

Base path:

```text
http://127.0.0.1:8089/api
```

Swagger:

```text
http://127.0.0.1:8089/swagger/rest.json
```

Static file:

```text
openapi/rest-openapi.json
```

### REST: Login As Admin

```bash
curl -s -X POST 'http://127.0.0.1:8089/api/login' \
  -H 'Content-Type: application/json' \
  --data '{"username":"admin_aurora","password":"adminpass1"}'
```

The response returns:

- `accessToken`
- `refreshToken`
- `sessionId`
- `expiresAt`
- `tokenId`

The access token is a dynamic JWT. Each login creates a new `jti`, `iat`, and `exp`.

### REST: Use Bearer Token

Use the `accessToken` in the `Authorization` header:

```bash
curl -s 'http://127.0.0.1:8089/api/admin/products' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

### REST: Validate Token

```bash
curl -s 'http://127.0.0.1:8089/api/validate' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

In vulnerable mode, JWT signature validation is intentionally weak.

### REST: Refresh Token

The access token expires after 2 minutes. The refresh token keeps the lab default validity of 15 minutes.

Use the refresh token to get another access token:

```bash
curl -s -X POST 'http://127.0.0.1:8089/api/refresh' \
  -H 'Content-Type: application/json' \
  --data '{"refreshToken":"YOUR_REFRESH_TOKEN"}'
```

Important vulnerable behavior:

- The refresh token is reusable.
- The refresh token is not rotated.
- The response returns a new dynamic JWT access token.
- The old refresh token still works.

This is intentional so a DAST scanner can detect refresh token reuse.

### REST: Admin List Products

```bash
curl -s 'http://127.0.0.1:8089/api/admin/products' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN'
```

Admins see product names, prices, and stock.

### REST: Admin Create Product

```bash
curl -s -X POST 'http://127.0.0.1:8089/api/admin/products' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN' \
  --data '{"sku":"SKU-REST-1","name":"REST Demo Product","price":77.70,"stock":7}'
```

Expected result:

```text
201 Created
Content-Type: application/json
```

### REST: Admin Edit Product With PUSH

```bash
curl -s -X PUSH 'http://127.0.0.1:8089/api/admin/products' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN' \
  --data '{"sku":"SKU-REST-1","price":88.80,"stock":8}'
```

Some tools do not support custom HTTP verbs well. For those tools, use this Swagger-friendly alias:

```bash
curl -s -X POST 'http://127.0.0.1:8089/api/admin/products/push' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN' \
  --data '{"sku":"SKU-REST-1","price":99.90}'
```

### REST: Admin Delete Product

```bash
curl -s -X DELETE 'http://127.0.0.1:8089/api/admin/products?sku=SKU-REST-1' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN'
```

### REST: Login As User

```bash
curl -s -X POST 'http://127.0.0.1:8089/api/login' \
  -H 'Content-Type: application/json' \
  --data '{"username":"user_apollo","password":"userpass1"}'
```

### REST: User List Products

```bash
curl -s 'http://127.0.0.1:8089/api/user/products' \
  -H 'Authorization: Bearer USER_ACCESS_TOKEN'
```

Users see product names and availability, but not prices.

### REST: User Forbidden Write

```bash
curl -i -X POST 'http://127.0.0.1:8089/api/user/products' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer USER_ACCESS_TOKEN' \
  --data '{"sku":"SKU-BLOCKED","name":"Blocked Product","price":1,"stock":1}'
```

Expected result:

```text
403 Forbidden
```

### REST: Audit Logs

```bash
curl -s 'http://127.0.0.1:8089/api/audit'
```

Authentication events are logged, including:

- login success
- login failure
- token validation
- missing bearer token
- refresh token use
- refresh token reuse
- logout

The app logs token fingerprints, not raw tokens.

## SOAP/XML API Interactions

The SOAP/XML API uses XML request and response bodies.

SOAP endpoint:

```text
http://127.0.0.1:8089/soap
```

WSDL:

```text
http://127.0.0.1:8089/soap?wsdl
```

SOAP/XML Swagger-style document:

```text
http://127.0.0.1:8089/swagger/xml.json
```

Static file:

```text
openapi/soap-openapi.json
```

### SOAP: Login As Admin

Use `/soap/auth` for scanner authentication scripts:

```bash
curl -s -X POST 'http://127.0.0.1:8089/soap/auth' \
  -H 'Content-Type: text/xml' \
  -H 'SOAPAction: Login' \
  --data-binary '<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:lab="urn:soap-dast-lab">
  <soap:Body>
    <lab:Login>
      <lab:Username>admin_aurora</lab:Username>
      <lab:Password>adminpass1</lab:Password>
    </lab:Login>
  </soap:Body>
</soap:Envelope>'
```

The SOAP response returns:

- `AccessToken`
- `RefreshToken`
- `SessionId`
- `ExpiresAt`
- `TokenId`

### SOAP: Validate Token

```bash
curl -s -X POST 'http://127.0.0.1:8089/soap/auth' \
  -H 'Content-Type: text/xml' \
  -H 'SOAPAction: ValidateToken' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN' \
  --data-binary '<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:lab="urn:soap-dast-lab">
  <soap:Body>
    <lab:ValidateToken/>
  </soap:Body>
</soap:Envelope>'
```

### SOAP: Refresh Token

Use `/soap/refreshtoken` for reauthentication:

```bash
curl -s -X POST 'http://127.0.0.1:8089/soap/refreshtoken' \
  -H 'Content-Type: text/xml' \
  -H 'SOAPAction: RefreshToken' \
  --data-binary '<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:lab="urn:soap-dast-lab">
  <soap:Body>
    <lab:RefreshToken>
      <lab:RefreshToken>YOUR_REFRESH_TOKEN</lab:RefreshToken>
    </lab:RefreshToken>
  </soap:Body>
</soap:Envelope>'
```

In vulnerable mode:

- `Rotated` is `false`
- The same refresh token is returned
- The old refresh token can be reused
- A new dynamic JWT access token is issued

### SOAP/XML: Admin List Products

```bash
curl -s 'http://127.0.0.1:8089/admin/products' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN'
```

Expected response:

```text
Content-Type: application/xml
```

### SOAP/XML: Admin Create Product

```bash
curl -s -X POST 'http://127.0.0.1:8089/admin/products' \
  -H 'Content-Type: application/xml' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN' \
  --data '<product><sku>SKU-XML-1</sku><name>XML Demo Product</name><price>55.50</price><stock>5</stock></product>'
```

Expected result:

```text
201 Created
Content-Type: application/xml
```

Some DAST tools wrap XML request examples as an escaped string, for example:

```xml
<?xml version='1.1' encoding='UTF-8'?><String>&lt;product&gt;&lt;sku&gt;SKU-900&lt;/sku&gt;&lt;name&gt;Scanner Lab Device&lt;/name&gt;&lt;price&gt;199.90&lt;/price&gt;&lt;stock&gt;7&lt;/stock&gt;&lt;/product&gt;</String>
```

The vulnerable app accepts both the direct `<product>` body and this scanner-style `<String>` wrapper.

### SOAP/XML: Admin Edit Product With PUSH

```bash
curl -s -X PUSH 'http://127.0.0.1:8089/admin/products' \
  -H 'Content-Type: application/xml' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN' \
  --data '<product><sku>SKU-XML-1</sku><price>66.60</price><stock>6</stock></product>'
```

### SOAP/XML: Admin Delete Product

```bash
curl -s -X DELETE 'http://127.0.0.1:8089/admin/products?sku=SKU-XML-1' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN'
```

### SOAP/XML: User List Products

```bash
curl -s 'http://127.0.0.1:8089/user/products' \
  -H 'Authorization: Bearer USER_ACCESS_TOKEN'
```

### SOAP/XML: User Forbidden Write

```bash
curl -i -X POST 'http://127.0.0.1:8089/user/products' \
  -H 'Content-Type: application/xml' \
  -H 'Authorization: Bearer USER_ACCESS_TOKEN' \
  --data '<product><sku>SKU-BLOCKED</sku><name>Blocked Product</name><price>1</price><stock>1</stock></product>'
```

Expected result:

```text
403 Forbidden
```

### SOAP/XML: Audit Logs

```bash
curl -s 'http://127.0.0.1:8089/audit'
```

### Login Tracking Evidence

Use `/login-tracking` to collect only authentication evidence:

```bash
curl -s 'http://127.0.0.1:8089/login-tracking?limit=100'
```

This route shows:

- every login attempt
- successful and failed logins
- expired token or expired session evidence
- refresh token requests
- new access token issuance
- refresh token usage
- token validation events

For a human-friendly executive view, open `/report` in a browser:

```bash
open 'http://127.0.0.1:8089/report?limit=100'
```

The report shows summary cards, a business-readable timeline, HTTP status code, source IP, `X-Forwarded-For`, user-agent, route, user, role, error, and important refresh-token notes.

The evidence is stored in memory and resets when the container restarts.

Expected response:

```text
Content-Type: application/xml
```

## Authentication Model

The authentication flow is intentionally simple:

```text
Login -> Access token + Refresh token
Use access token as Bearer token
Access token expires after 2 minutes; refresh token remains valid for 15 minutes
Use refresh token to get a new dynamic JWT
In vulnerable mode, the same refresh token can be reused
```

JWT dynamic fields:

- `iat`: issued at
- `exp`: expires at
- `jti`: unique token id
- `sid`: session id
- `role`: `admin` or `user`

Important testing note: sessions are stored in memory. If the container restarts, old JWTs may return `session_not_found`. In that case, login again and use the new bearer token.

## Fuzzing Checklist

REST JSON targets:

- `POST /api/login`
- `POST /api/refresh`
- `GET /api/validate`
- `GET /api/admin/products`
- `POST /api/admin/products`
- `PUSH /api/admin/products`
- `DELETE /api/admin/products`
- `GET /api/user/products`
- `POST /api/user/products`
- `GET /api/products/eletronico?q=camera' OR '1'='1`
- `GET /api/products/smarphone?id=1 OR 1=1`
- `GET /api/products/laptops?sort=name; DROP TABLE products`
- `GET /api/products/books?min_value=0 UNION SELECT username,password,1,1,1 FROM users`
- `GET /api/ecommerce/categories`
- `GET /api/ecommerce/brands?q=orion`
- `GET /api/ecommerce/deals?status=active`
- `GET /api/ecommerce/cart`
- `GET /api/ecommerce/orders`
- `GET /api/ecommerce/reviews`
- `GET /api/ecommerce/warranty`
- `GET /api/ecommerce/shipping`
- `GET /api/ecommerce/stores`
- `GET /api/ecommerce/support`
- `GET /comments?preview=<script>alert(1)</script>`
- `POST /comments`

SOAP/XML targets:

- `POST /soap/auth` with `SOAPAction: Login`
- `POST /soap/refreshtoken` with `SOAPAction: RefreshToken`
- `POST /soap/auth` with `SOAPAction: ValidateToken`
- `POST /soap` with `SOAPAction: SearchUser`
- `POST /soap` with `DOCTYPE` / `ENTITY`
- `POST /admin/products`
- `PUSH /admin/products`
- `DELETE /admin/products`
- `GET /products/eletronico?q=camera' OR '1'='1`
- `GET /products/smarphone?id=1 OR 1=1`
- `GET /products/laptops?promotion=yes`
- `GET /products/books?q=SQL' OR '1'='1`
- `GET /ecommerce/categories`
- `GET /ecommerce/brands?q=orion`
- `GET /ecommerce/deals?status=active`
- `GET /ecommerce/cart`
- `GET /ecommerce/orders`
- `GET /ecommerce/reviews`
- `GET /ecommerce/warranty`
- `GET /ecommerce/shipping`
- `GET /ecommerce/stores`
- `GET /ecommerce/support`

Authentication tests:

- Missing bearer token
- Invalid JWT
- Expired JWT after 2 minutes
- Modified JWT payload
- Modified JWT signature
- `alg=none`
- Refresh token reuse
- Session fixation with `X-Fixed-Session-Id`
- User token trying admin route

## AWS ECS/Fargate

The repository includes:

- `deploy/aws/ecs-task-definition.json`
- `deploy/aws/create-ecs-fargate.sh`

The ECS task exposes the vulnerable app on container port `8089`.

High-level flow:

```bash
export AWS_REGION=us-east-1
export AWS_ACCOUNT_ID=123456789012
export SUBNETS=subnet-aaa111,subnet-bbb222
export SECURITY_GROUPS=sg-abc123
export PUBLIC_HOST=your-public-dns-or-load-balancer
export IMAGE_PLATFORM=linux/amd64

chmod +x deploy/aws/create-ecs-fargate.sh
./deploy/aws/create-ecs-fargate.sh
```

The script uses `docker buildx build --platform linux/amd64 --push` by default. This avoids cloud runtime errors when the image was built on an ARM machine such as an Apple Silicon Mac.

Test:

```text
http://YOUR_ECS_ENDPOINT:8089/swagger/rest.json
http://YOUR_ECS_ENDPOINT:8089/swagger/xml.json
http://YOUR_ECS_ENDPOINT:8089/soap?wsdl
```

## Azure Container Apps

The repository includes:

- `deploy/azure/create-container-apps.sh`
- `deploy/azure/container-app-vulnerable.yaml`

High-level flow:

```bash
az login
az extension add --name containerapp --upgrade

export LOCATION=eastus
export PROJECT_NAME=rest-soap-labs
export RESOURCE_GROUP=rg-rest-soap-labs
export ENVIRONMENT_NAME=cae-rest-soap-labs
export CONTAINER_APP_NAME=ca-rest-soap-labs
export ACR_NAME=restsoaplabs
export IMAGE_PLATFORM=linux/amd64

chmod +x deploy/azure/create-container-apps.sh
./deploy/azure/create-container-apps.sh
```

The script uses `docker buildx build --platform linux/amd64 --push` by default. This fixes Azure errors like `no child with platform linux/amd64 in index`.

Default Azure names:

```text
Project name:           rest-soap-labs
Resource group:         rg-rest-soap-labs
Container Apps env:     cae-rest-soap-labs
Container App:          ca-rest-soap-labs
Image name:             rest-soap-labs
ACR:                    restsoaplabs
```

Azure Container Registry is the only exception to the hyphenated name because ACR names cannot contain hyphens. If `restsoaplabs` is already taken globally, set another alphanumeric value with `ACR_NAME`.

Test:

```text
https://YOUR_CONTAINER_APP_FQDN/swagger/rest.json
https://YOUR_CONTAINER_APP_FQDN/swagger/xml.json
https://YOUR_CONTAINER_APP_FQDN/soap?wsdl
```

---

# Laboratorio Vulneravel SOAP e REST DAST

## Portugues

### Objetivo

Este repositorio e um laboratorio de seguranca vulneravel de proposito para demonstrar ataques contra APIs SOAP/XML e REST/JSON em ambiente autorizado.

A aplicacao roda em uma porta:

```text
http://127.0.0.1:8089
```

Ela expoe dois estilos de API:

- API REST com JSON em `/api`
- API SOAP/XML em `/soap`
- Rota dedicada de login e validacao de token SOAP em `/soap/auth`
- Rota dedicada de refresh token SOAP em `/soap/refreshtoken`

Documentos Swagger/OpenAPI:

- Swagger da REST API: `http://127.0.0.1:8089/swagger/rest.json`
- Documento estilo Swagger para SOAP/XML: `http://127.0.0.1:8089/swagger/xml.json`
- WSDL: `http://127.0.0.1:8089/soap?wsdl`

Arquivos OpenAPI estaticos para importar:

- `openapi/rest-openapi.json`
- `openapi/soap-openapi.json`

Armazenamento relacional:

- O laboratorio usa SQLite por padrao em `/tmp/rest_soap_labs.db`.
- Altere o caminho com `SOAP_DAST_DB_PATH`.
- Catalogo de produtos, registros de e-commerce e comentarios XSS ficam em tabelas relacionais.

Scripts de autenticacao DAST e validadores:

- `scripts/dast/SRM_Soap.js`
- `scripts/dast/SRM_Rest.js`
- `scripts/dast/test-soap-auth-route.js`
- `scripts/dast/test-rest-auth-route.js`

### Vulnerabilidades Intencionais

Este laboratorio e vulneravel de proposito:

- Aceita JWT `alg=none`
- Bypass de assinatura JWT
- Reuso de refresh token
- Session fixation com `X-Fixed-Session-Id`
- Cookie sem atributos seguros no modo vulneravel
- IDOR no acesso de contas
- Reflexao XML insegura
- Sinal positivo para `DOCTYPE` / `ENTITY`
- Reflexao com TRACE
- Vinculo fraco de sessao
- Auditoria completa de interacoes HTTP/SOAP, respostas, login, validacao de token e uso de refresh token
- Evidencias dedicadas de login em `/login-tracking`
- Relatorio executivo de autenticacao em `/report`

Rode apenas em ambientes seus ou onde voce tem autorizacao para testar.

### Arquivos

- `server.py`: usuarios, tokens, produtos, helpers XML e handlers base
- `vulnerable_server.py`: aplicacao vulneravel REST/JSON e SOAP/XML
- `run_both.py`: inicia o modo selecionado por `APP_MODE`
- `Dockerfile`: imagem do container
- `docker-compose.yml`: aplicacao vulneravel local na porta `8089`
- `requests.http`: exemplos SOAP
- `vulnerable-requests.http`: exemplos SOAP vulneraveis
- `admin-user-requests.http`: exemplos XML de produtos
- `rest-json-requests.http`: exemplos REST JSON
- `openapi/rest-openapi.json`: arquivo OpenAPI estatico para importar REST JSON
- `openapi/soap-openapi.json`: arquivo estilo OpenAPI estatico para importar SOAP/XML
- `deploy/aws/`: exemplos AWS ECS/Fargate
- `deploy/azure/`: exemplos Azure Container Apps

### Usuarios

Usuarios admin:

| Usuario | Senha |
| --- | --- |
| `admin_aurora` | `adminpass1` |
| `admin_boreal` | `adminpass2` |
| `admin_cosmos` | `adminpass3` |
| `admin_delta` | `adminpass4` |
| `admin_equinox` | `adminpass5` |

Usuarios comuns:

| Usuario | Senha |
| --- | --- |
| `user_apollo` | `userpass1` |
| `user_bianca` | `userpass2` |
| `user_cairo` | `userpass3` |
| `user_diana` | `userpass4` |
| `user_elias` | `userpass5` |

### Rodar Localmente Com Docker

Build e start:

```bash
docker compose up --build -d
```

Verificar o container:

```bash
docker compose ps
```

Ver logs:

```bash
docker compose logs -f
```

Parar:

```bash
docker compose down
```

Checagens:

```bash
curl -i 'http://127.0.0.1:8089/api'
curl -i 'http://127.0.0.1:8089/soap?wsdl'
curl -i 'http://127.0.0.1:8089/swagger/rest.json'
curl -i 'http://127.0.0.1:8089/swagger/xml.json'
```

## Interacoes Da REST API

A REST API usa corpos JSON em requisicoes e respostas.

Caminho base:

```text
http://127.0.0.1:8089/api
```

Swagger:

```text
http://127.0.0.1:8089/swagger/rest.json
```

Arquivo estatico:

```text
openapi/rest-openapi.json
```

### REST: Login Como Admin

```bash
curl -s -X POST 'http://127.0.0.1:8089/api/login' \
  -H 'Content-Type: application/json' \
  --data '{"username":"admin_aurora","password":"adminpass1"}'
```

A resposta retorna:

- `accessToken`
- `refreshToken`
- `sessionId`
- `expiresAt`
- `tokenId`

O access token e um JWT dinamico. Cada login cria novos valores para `jti`, `iat` e `exp`.

### REST: Usar Bearer Token

Use o `accessToken` no header `Authorization`:

```bash
curl -s 'http://127.0.0.1:8089/api/admin/products' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

### REST: Validar Token

```bash
curl -s 'http://127.0.0.1:8089/api/validate' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

No modo vulneravel, a validacao de assinatura JWT e fraca de proposito.

### REST: Refresh Token

O access token expira depois de 2 minutos. O refresh token mantem a validade padrao do laboratorio de 15 minutos.

Use o refresh token para pegar outro access token:

```bash
curl -s -X POST 'http://127.0.0.1:8089/api/refresh' \
  -H 'Content-Type: application/json' \
  --data '{"refreshToken":"YOUR_REFRESH_TOKEN"}'
```

Comportamento vulneravel importante:

- O refresh token e reutilizavel.
- O refresh token nao e rotacionado.
- A resposta retorna um novo access token JWT dinamico.
- O refresh token antigo continua funcionando.

Isso e intencional para permitir que um scanner DAST detecte reuso de refresh token.

### REST: Admin Lista Produtos

```bash
curl -s 'http://127.0.0.1:8089/api/admin/products' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN'
```

Admins veem nome, preco e estoque dos produtos.

### REST: Admin Cria Produto

```bash
curl -s -X POST 'http://127.0.0.1:8089/api/admin/products' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN' \
  --data '{"sku":"SKU-REST-1","name":"Produto REST Demo","price":77.70,"stock":7}'
```

Resultado esperado:

```text
201 Created
Content-Type: application/json
```

### REST: Admin Edita Produto Com PUSH

```bash
curl -s -X PUSH 'http://127.0.0.1:8089/api/admin/products' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN' \
  --data '{"sku":"SKU-REST-1","price":88.80,"stock":8}'
```

Algumas ferramentas nao suportam bem verbos HTTP customizados. Para essas ferramentas, use o alias amigavel para Swagger:

```bash
curl -s -X POST 'http://127.0.0.1:8089/api/admin/products/push' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN' \
  --data '{"sku":"SKU-REST-1","price":99.90}'
```

### REST: Admin Deleta Produto

```bash
curl -s -X DELETE 'http://127.0.0.1:8089/api/admin/products?sku=SKU-REST-1' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN'
```

### REST: Login Como User

```bash
curl -s -X POST 'http://127.0.0.1:8089/api/login' \
  -H 'Content-Type: application/json' \
  --data '{"username":"user_apollo","password":"userpass1"}'
```

### REST: User Lista Produtos

```bash
curl -s 'http://127.0.0.1:8089/api/user/products' \
  -H 'Authorization: Bearer USER_ACCESS_TOKEN'
```

Users veem nomes e disponibilidade, mas nao veem precos.

### REST: User Com Escrita Proibida

```bash
curl -i -X POST 'http://127.0.0.1:8089/api/user/products' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer USER_ACCESS_TOKEN' \
  --data '{"sku":"SKU-BLOCKED","name":"Produto Bloqueado","price":1,"stock":1}'
```

Resultado esperado:

```text
403 Forbidden
```

### REST: Logs De Auditoria

```bash
curl -s 'http://127.0.0.1:8089/api/audit'
```

Eventos de autenticacao sao logados, incluindo:

- login com sucesso
- falha de login
- validacao de token
- bearer token ausente
- uso de refresh token
- reuso de refresh token
- logout

A aplicacao grava fingerprints dos tokens, nao os tokens reais.

## Interacoes Da API SOAP/XML

A API SOAP/XML usa corpos XML em requisicoes e respostas.

Endpoint SOAP:

```text
http://127.0.0.1:8089/soap
```

WSDL:

```text
http://127.0.0.1:8089/soap?wsdl
```

Documento estilo Swagger para SOAP/XML:

```text
http://127.0.0.1:8089/swagger/xml.json
```

Arquivo estatico:

```text
openapi/soap-openapi.json
```

### SOAP: Login Como Admin

Use `/soap/auth` para scripts de autenticacao do scanner:

```bash
curl -s -X POST 'http://127.0.0.1:8089/soap/auth' \
  -H 'Content-Type: text/xml' \
  -H 'SOAPAction: Login' \
  --data-binary '<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:lab="urn:soap-dast-lab">
  <soap:Body>
    <lab:Login>
      <lab:Username>admin_aurora</lab:Username>
      <lab:Password>adminpass1</lab:Password>
    </lab:Login>
  </soap:Body>
</soap:Envelope>'
```

A resposta SOAP retorna:

- `AccessToken`
- `RefreshToken`
- `SessionId`
- `ExpiresAt`
- `TokenId`

### SOAP: Validar Token

```bash
curl -s -X POST 'http://127.0.0.1:8089/soap/auth' \
  -H 'Content-Type: text/xml' \
  -H 'SOAPAction: ValidateToken' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN' \
  --data-binary '<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:lab="urn:soap-dast-lab">
  <soap:Body>
    <lab:ValidateToken/>
  </soap:Body>
</soap:Envelope>'
```

### SOAP: Refresh Token

Use `/soap/refreshtoken` para reautenticacao:

```bash
curl -s -X POST 'http://127.0.0.1:8089/soap/refreshtoken' \
  -H 'Content-Type: text/xml' \
  -H 'SOAPAction: RefreshToken' \
  --data-binary '<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:lab="urn:soap-dast-lab">
  <soap:Body>
    <lab:RefreshToken>
      <lab:RefreshToken>YOUR_REFRESH_TOKEN</lab:RefreshToken>
    </lab:RefreshToken>
  </soap:Body>
</soap:Envelope>'
```

No modo vulneravel:

- `Rotated` e `false`
- O mesmo refresh token e retornado
- O refresh token antigo pode ser reutilizado
- Um novo access token JWT dinamico e emitido

### SOAP/XML: Admin Lista Produtos

```bash
curl -s 'http://127.0.0.1:8089/admin/products' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN'
```

Resposta esperada:

```text
Content-Type: application/xml
```

### SOAP/XML: Admin Cria Produto

```bash
curl -s -X POST 'http://127.0.0.1:8089/admin/products' \
  -H 'Content-Type: application/xml' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN' \
  --data '<product><sku>SKU-XML-1</sku><name>Produto XML Demo</name><price>55.50</price><stock>5</stock></product>'
```

Resultado esperado:

```text
201 Created
Content-Type: application/xml
```

Algumas ferramentas DAST embrulham o XML do exemplo como uma string escapada, por exemplo:

```xml
<?xml version='1.1' encoding='UTF-8'?><String>&lt;product&gt;&lt;sku&gt;SKU-900&lt;/sku&gt;&lt;name&gt;Scanner Lab Device&lt;/name&gt;&lt;price&gt;199.90&lt;/price&gt;&lt;stock&gt;7&lt;/stock&gt;&lt;/product&gt;</String>
```

A aplicacao vulneravel aceita tanto o corpo direto `<product>` quanto esse wrapper `<String>` usado por scanners.

### SOAP/XML: Admin Edita Produto Com PUSH

```bash
curl -s -X PUSH 'http://127.0.0.1:8089/admin/products' \
  -H 'Content-Type: application/xml' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN' \
  --data '<product><sku>SKU-XML-1</sku><price>66.60</price><stock>6</stock></product>'
```

### SOAP/XML: Admin Deleta Produto

```bash
curl -s -X DELETE 'http://127.0.0.1:8089/admin/products?sku=SKU-XML-1' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN'
```

### SOAP/XML: User Lista Produtos

```bash
curl -s 'http://127.0.0.1:8089/user/products' \
  -H 'Authorization: Bearer USER_ACCESS_TOKEN'
```

### SOAP/XML: User Com Escrita Proibida

```bash
curl -i -X POST 'http://127.0.0.1:8089/user/products' \
  -H 'Content-Type: application/xml' \
  -H 'Authorization: Bearer USER_ACCESS_TOKEN' \
  --data '<product><sku>SKU-BLOCKED</sku><name>Produto Bloqueado</name><price>1</price><stock>1</stock></product>'
```

Resultado esperado:

```text
403 Forbidden
```

### SOAP/XML: Logs De Auditoria

```bash
curl -s 'http://127.0.0.1:8089/audit'
```

### Evidencias De Login

Use `/login-tracking` para coletar somente evidencias de autenticacao:

```bash
curl -s 'http://127.0.0.1:8089/login-tracking?limit=100'
```

Essa rota mostra:

- todas as tentativas de login
- logins com sucesso e falhas de login
- evidencias de token expirado ou sessao expirada
- solicitacoes de refresh token
- emissao de novo access token
- uso do refresh token
- eventos de validacao de token

Para uma visao executiva amigavel, abra `/report` no navegador:

```bash
open 'http://127.0.0.1:8089/report?limit=100'
```

O relatorio mostra cards de resumo, linha do tempo em linguagem de negocio, HTTP status code, IP de origem, `X-Forwarded-For`, user-agent, rota, usuario, role, erro e notas importantes sobre refresh token.

As evidencias ficam em memoria e sao apagadas quando o container reinicia.

Resposta esperada:

```text
Content-Type: application/xml
```

## Modelo De Autenticacao

O fluxo de autenticacao e simples:

```text
Login -> Access token + Refresh token
Usa access token como Bearer token
Access token expira depois de 2 minutos; refresh token continua valido por 15 minutos
Usa refresh token para pegar novo JWT dinamico
No modo vulneravel, o mesmo refresh token pode ser reutilizado
```

Campos dinamicos do JWT:

- `iat`: emitido em
- `exp`: expira em
- `jti`: id unico do token
- `sid`: id da sessao
- `role`: `admin` ou `user`

Nota importante para testes: as sessoes ficam em memoria. Se o container reiniciar, JWTs antigos podem retornar `session_not_found`. Nesse caso, faca login de novo e use o novo bearer token.

## Checklist De Fuzzing

Alvos REST JSON:

- `POST /api/login`
- `POST /api/refresh`
- `GET /api/validate`
- `GET /api/admin/products`
- `POST /api/admin/products`
- `PUSH /api/admin/products`
- `DELETE /api/admin/products`
- `GET /api/user/products`
- `POST /api/user/products`
- `GET /api/products/eletronico?q=camera' OR '1'='1`
- `GET /api/products/smarphone?id=1 OR 1=1`
- `GET /api/products/laptops?sort=name; DROP TABLE products`
- `GET /api/products/books?min_value=0 UNION SELECT username,password,1,1,1 FROM users`
- `GET /api/ecommerce/categories`
- `GET /api/ecommerce/brands?q=orion`
- `GET /api/ecommerce/deals?status=active`
- `GET /api/ecommerce/cart`
- `GET /api/ecommerce/orders`
- `GET /api/ecommerce/reviews`
- `GET /api/ecommerce/warranty`
- `GET /api/ecommerce/shipping`
- `GET /api/ecommerce/stores`
- `GET /api/ecommerce/support`
- `GET /comments?preview=<script>alert(1)</script>`
- `POST /comments`

Alvos SOAP/XML:

- `POST /soap/auth` com `SOAPAction: Login`
- `POST /soap/refreshtoken` com `SOAPAction: RefreshToken`
- `POST /soap/auth` com `SOAPAction: ValidateToken`
- `POST /soap` com `SOAPAction: SearchUser`
- `POST /soap` com `DOCTYPE` / `ENTITY`
- `POST /admin/products`
- `PUSH /admin/products`
- `DELETE /admin/products`
- `GET /products/eletronico?q=camera' OR '1'='1`
- `GET /products/smarphone?id=1 OR 1=1`
- `GET /products/laptops?promotion=yes`
- `GET /products/books?q=SQL' OR '1'='1`
- `GET /ecommerce/categories`
- `GET /ecommerce/brands?q=orion`
- `GET /ecommerce/deals?status=active`
- `GET /ecommerce/cart`
- `GET /ecommerce/orders`
- `GET /ecommerce/reviews`
- `GET /ecommerce/warranty`
- `GET /ecommerce/shipping`
- `GET /ecommerce/stores`
- `GET /ecommerce/support`

Testes de autenticacao:

- Bearer token ausente
- JWT invalido
- JWT expirado depois de 2 minutos
- Payload JWT alterado
- Assinatura JWT alterada
- `alg=none`
- Reuso de refresh token
- Session fixation com `X-Fixed-Session-Id`
- Token user tentando rota admin

## AWS ECS/Fargate

O repositorio inclui:

- `deploy/aws/ecs-task-definition.json`
- `deploy/aws/create-ecs-fargate.sh`

O task ECS expoe a aplicacao vulneravel na porta de container `8089`.

Fluxo geral:

```bash
export AWS_REGION=us-east-1
export AWS_ACCOUNT_ID=123456789012
export SUBNETS=subnet-aaa111,subnet-bbb222
export SECURITY_GROUPS=sg-abc123
export PUBLIC_HOST=seu-dns-publico-ou-load-balancer
export IMAGE_PLATFORM=linux/amd64

chmod +x deploy/aws/create-ecs-fargate.sh
./deploy/aws/create-ecs-fargate.sh
```

O script usa `docker buildx build --platform linux/amd64 --push` por padrao. Isso evita erros em runtimes cloud quando a imagem foi buildada em maquina ARM, como Mac Apple Silicon.

Teste:

```text
http://YOUR_ECS_ENDPOINT:8089/swagger/rest.json
http://YOUR_ECS_ENDPOINT:8089/swagger/xml.json
http://YOUR_ECS_ENDPOINT:8089/soap?wsdl
```

## Azure Container Apps

O repositorio inclui:

- `deploy/azure/create-container-apps.sh`
- `deploy/azure/container-app-vulnerable.yaml`

Fluxo geral:

```bash
az login
az extension add --name containerapp --upgrade

export LOCATION=eastus
export PROJECT_NAME=rest-soap-labs
export RESOURCE_GROUP=rg-rest-soap-labs
export ENVIRONMENT_NAME=cae-rest-soap-labs
export CONTAINER_APP_NAME=ca-rest-soap-labs
export ACR_NAME=restsoaplabs
export IMAGE_PLATFORM=linux/amd64

chmod +x deploy/azure/create-container-apps.sh
./deploy/azure/create-container-apps.sh
```

O script usa `docker buildx build --platform linux/amd64 --push` por padrao. Isso corrige erros da Azure como `no child with platform linux/amd64 in index`.

Nomes padrao na Azure:

```text
Project name:           rest-soap-labs
Resource group:         rg-rest-soap-labs
Container Apps env:     cae-rest-soap-labs
Container App:          ca-rest-soap-labs
Image name:             rest-soap-labs
ACR:                    restsoaplabs
```

Azure Container Registry e a unica excecao ao nome com hifen porque ACR nao aceita hifens. Se `restsoaplabs` ja estiver ocupado globalmente, defina outro valor alfanumerico com `ACR_NAME`.

Teste:

```text
https://YOUR_CONTAINER_APP_FQDN/swagger/rest.json
https://YOUR_CONTAINER_APP_FQDN/swagger/xml.json
https://YOUR_CONTAINER_APP_FQDN/soap?wsdl
```
