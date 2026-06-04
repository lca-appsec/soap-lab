# SOAP DAST Lab

English | Portugues

This project is a small security testing playground for demonstrating SOAP and REST attacks in an authorized lab.

- Port `8089`: intentionally vulnerable API.
- XML/SOAP API: `/soap`
- REST JSON API: `/api`
- REST Swagger/OpenAPI: `/swagger/rest.json`
- XML/SOAP Swagger/OpenAPI: `/swagger/xml.json`

You use it to test DAST scanners, fuzzing, JWT login, refresh tokens, session cookies, HTTP verbs, admin routes, and user routes.

Este projeto e um pequeno laboratorio para demonstrar ataques em SOAP e REST em ambiente autorizado.

- Porta `8089`: API vulneravel de proposito.
- API XML/SOAP: `/soap`
- API REST JSON: `/api`
- Swagger/OpenAPI REST: `/swagger/rest.json`
- Swagger/OpenAPI XML/SOAP: `/swagger/xml.json`

Voce usa para testar scanners DAST, fuzzing, login JWT, refresh token, cookie de sessao, verbos HTTP, rotas de admin e rotas de user.

---

## What Was Built

The container starts only the intentionally vulnerable Python application:

- `vulnerable_server.py`: intentionally vulnerable version on `8089`.

The vulnerable application supports:

- SOAP login with JWT.
- REST JSON login with JWT.
- Dynamic JWT access tokens.
- Access token expiration after **3 minutes**.
- Refresh token flow to continue the session.
- Session cookie named `DASTSESSION`.
- Ten users at the same time.
- Five admin users.
- Five normal users.
- Product routes for testing HTTP verbs.
- Swagger/OpenAPI for REST JSON.
- Swagger/OpenAPI-style documentation for XML/SOAP.

The vulnerable app adds intentional problems:

- JWT `alg=none`.
- JWT signature bypass.
- IDOR.
- Session fixation.
- Refresh token reuse.
- TRACE reflection.
- Unsafe XML reflection.

---

## O Que Foi Construido

O container inicia somente a aplicacao Python vulneravel de proposito:

- `vulnerable_server.py`: versao vulneravel de proposito na porta `8089`.

A aplicacao vulneravel suporta:

- Login SOAP com JWT.
- Login REST JSON com JWT.
- Token JWT dinamico.
- Access token expira depois de **3 minutos**.
- Refresh token para continuar a sessao.
- Cookie de sessao chamado `DASTSESSION`.
- Dez usuarios autenticados ao mesmo tempo.
- Cinco usuarios admin.
- Cinco usuarios comuns.
- Rotas de produtos para testar verbos HTTP.
- Swagger/OpenAPI para REST JSON.
- Documentacao estilo Swagger/OpenAPI para XML/SOAP.

A aplicacao vulneravel adiciona problemas de proposito:

- JWT `alg=none`.
- Bypass de assinatura JWT.
- IDOR.
- Session fixation.
- Reuso de refresh token.
- Reflexao com TRACE.
- Reflexao XML insegura.

---

## Files

- `server.py`: shared helpers, users, tokens, products, XML helpers.
- `vulnerable_server.py`: vulnerable XML/SOAP and REST JSON server.
- `run_both.py`: starts the selected app mode; Docker Compose uses `APP_MODE=vulnerable`.
- `Dockerfile`: builds the container image.
- `docker-compose.yml`: runs the vulnerable app locally on `8089`.
- `deploy/aws/ecs-task-definition.json`: AWS ECS/Fargate task definition example.
- `deploy/aws/create-ecs-fargate.sh`: helper script to build, push to ECR, and create an ECS service.
- `deploy/azure/create-container-apps.sh`: helper script to build, push to ACR, and create Azure Container Apps.
- `deploy/azure/container-app-vulnerable.yaml`: Azure Container Apps YAML for the vulnerable app.
- `requests.http`: SOAP examples.
- `vulnerable-requests.http`: vulnerable examples.
- `admin-user-requests.http`: admin/user product route examples.
- `rest-json-requests.http`: REST JSON route and Swagger examples.

---

## Users And Passwords

Admin users:

| Username | Password |
| --- | --- |
| `admin_aurora` | `R9v!tQ2mZx#4` |
| `admin_boreal` | `K7p@Lw3sDn$8` |
| `admin_cosmos` | `M4x#Qr8nVp!1` |
| `admin_delta` | `H2s$Yu6cJk@9` |
| `admin_equinox` | `T5n!Ba9wLf#3` |

Normal users:

| Username | Password |
| --- | --- |
| `user_apollo` | `P6d@Xe1mRt$7` |
| `user_bianca` | `W8k#No2vHs!5` |
| `user_cairo` | `C3y$Pa7qZm@2` |
| `user_diana` | `L1f!Gw5rKb#6` |
| `user_elias` | `V9m@Sd4xQh$1` |

---

## Run With Docker Desktop

Imagine Docker is a lunchbox. We put the vulnerable app inside the lunchbox and open one little window: `8089`.

Build and start:

```bash
docker compose up --build -d
```

Check if it is running:

```bash
docker compose ps
```

Open the XML/SOAP WSDL:

```text
http://127.0.0.1:8089/soap?wsdl
```

Open REST Swagger:

```text
http://127.0.0.1:8089/swagger/rest.json
```

Open XML/SOAP Swagger:

```text
http://127.0.0.1:8089/swagger/xml.json
```

See logs:

```bash
docker compose logs -f
```

Stop:

```bash
docker compose down
```

---

## Rodar Com Docker Desktop

Imagine que o Docker e uma lancheira. Colocamos a aplicacao vulneravel dentro da lancheira e abrimos uma janelinha: `8089`.

Build e start:

```bash
docker compose up --build -d
```

Ver se esta rodando:

```bash
docker compose ps
```

Abrir o WSDL XML/SOAP:

```text
http://127.0.0.1:8089/soap?wsdl
```

Abrir o WSDL vulneravel:

```text
http://127.0.0.1:8089/soap?wsdl
```

Ver logs:

```bash
docker compose logs -f
```

Parar:

```bash
docker compose down
```

---

## API Surfaces

The vulnerable lab exposes two API styles on the same port:

XML/SOAP:

- `GET /soap?wsdl`
- `POST /soap`
- `GET /swagger/xml.json`

REST JSON:

- `GET /api`
- `POST /api/login`
- `POST /api/refresh`
- `GET /api/validate`
- `GET /api/admin/products`
- `POST /api/admin/products`
- `PUSH /api/admin/products`
- `POST /api/admin/products/push` as a Swagger-friendly alias for `PUSH`
- `DELETE /api/admin/products?sku=SKU-100`
- `GET /api/user/products`
- `GET /api/audit`
- `GET /swagger/rest.json`

REST JSON login:

```bash
curl -s -X POST 'http://127.0.0.1:8089/api/login' \
  -H 'Content-Type: application/json' \
  --data '{"username":"admin_aurora","password":"R9v!tQ2mZx#4"}'
```

Use the returned token:

```bash
curl -s 'http://127.0.0.1:8089/api/admin/products' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

REST JSON refresh:

```bash
curl -s -X POST 'http://127.0.0.1:8089/api/refresh' \
  -H 'Content-Type: application/json' \
  --data '{"refreshToken":"YOUR_REFRESH_TOKEN"}'
```

Swagger/OpenAPI:

```text
http://127.0.0.1:8089/swagger/rest.json
http://127.0.0.1:8089/swagger/xml.json
```

---

## Superficies De API

O laboratorio vulneravel expoe dois estilos de API na mesma porta:

XML/SOAP:

- `GET /soap?wsdl`
- `POST /soap`
- `GET /swagger/xml.json`

REST JSON:

- `GET /api`
- `POST /api/login`
- `POST /api/refresh`
- `GET /api/validate`
- `GET /api/admin/products`
- `POST /api/admin/products`
- `PUSH /api/admin/products`
- `POST /api/admin/products/push` como alias amigavel para Swagger do verbo `PUSH`
- `DELETE /api/admin/products?sku=SKU-100`
- `GET /api/user/products`
- `GET /api/audit`
- `GET /swagger/rest.json`

Login REST JSON:

```bash
curl -s -X POST 'http://127.0.0.1:8089/api/login' \
  -H 'Content-Type: application/json' \
  --data '{"username":"admin_aurora","password":"R9v!tQ2mZx#4"}'
```

Use o token retornado:

```bash
curl -s 'http://127.0.0.1:8089/api/admin/products' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

Refresh REST JSON:

```bash
curl -s -X POST 'http://127.0.0.1:8089/api/refresh' \
  -H 'Content-Type: application/json' \
  --data '{"refreshToken":"YOUR_REFRESH_TOKEN"}'
```

Swagger/OpenAPI:

```text
http://127.0.0.1:8089/swagger/rest.json
http://127.0.0.1:8089/swagger/xml.json
```

---

## Login: Get Access Token And Refresh Token

The access token is like a small visitor badge. It works for 3 minutes.

The refresh token is like asking the front desk: "Please give me a new badge so I can continue."

Admin login:

```bash
curl -s -X POST 'http://127.0.0.1:8089/soap' \
  -H 'Content-Type: text/xml' \
  -H 'SOAPAction: Login' \
  --data-binary '<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:lab="urn:soap-dast-lab">
  <soap:Body>
    <lab:Login>
      <lab:Username>admin_aurora</lab:Username>
      <lab:Password>R9v!tQ2mZx#4</lab:Password>
    </lab:Login>
  </soap:Body>
</soap:Envelope>'
```

The response contains:

- `AccessToken`
- `RefreshToken`
- `SessionId`
- `ExpiresAt`
- `TokenId`

Copy the `AccessToken`. Use it like this:

```bash
curl -s 'http://127.0.0.1:8089/admin/products' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

---

## Login: Pegar Access Token E Refresh Token

O access token e como um cracha pequeno. Ele funciona por 3 minutos.

O refresh token e como falar na recepcao: "Me da outro cracha para eu continuar."

Login admin:

```bash
curl -s -X POST 'http://127.0.0.1:8089/soap' \
  -H 'Content-Type: text/xml' \
  -H 'SOAPAction: Login' \
  --data-binary '<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:lab="urn:soap-dast-lab">
  <soap:Body>
    <lab:Login>
      <lab:Username>admin_aurora</lab:Username>
      <lab:Password>R9v!tQ2mZx#4</lab:Password>
    </lab:Login>
  </soap:Body>
</soap:Envelope>'
```

A resposta contem:

- `AccessToken`
- `RefreshToken`
- `SessionId`
- `ExpiresAt`
- `TokenId`

Copie o `AccessToken`. Use assim:

```bash
curl -s 'http://127.0.0.1:8089/admin/products' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

---

## Refresh Token: Continue After 3 Minutes

Wait 3 minutes, or keep using the app until the access token expires.

Then call `RefreshToken`:

```bash
curl -s -X POST 'http://127.0.0.1:8089/soap' \
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

In the vulnerable app, the response gives you:

- A new `AccessToken`.
- The same reusable `RefreshToken`.
- `Rotated` equals `false`.

Now use the new `AccessToken`:

```bash
curl -s 'http://127.0.0.1:8089/admin/products' \
  -H 'Authorization: Bearer NEW_ACCESS_TOKEN'
```

Try the old refresh token again. The vulnerable app accepts it again. That is intentional, and it demonstrates refresh token reuse.

```text
refresh token reuse allowed
```

That proves the vulnerable refresh token behavior is detectable.

---

## How Authentication Works

The authentication flow has four small pieces:

1. **Username and password**
   - The user sends credentials to the SOAP `Login` operation.
   - If they are correct, the API creates a session.

2. **Access token**
   - The API returns an `AccessToken`.
   - This token is a JWT.
   - It is used in protected routes with:

```text
Authorization: Bearer YOUR_ACCESS_TOKEN
```

3. **Dynamic JWT**
   - The JWT is dynamic because every login and refresh creates a new token.
   - The fields `iat`, `exp`, and `jti` change.
   - `iat` means "issued at".
   - `exp` means "expires at".
   - `jti` is the unique token id.
   - The access token expires after **3 minutes**.

4. **Refresh token**
   - When the access token expires, call SOAP `RefreshToken`.
   - The vulnerable app returns a new access token.
   - The old refresh token can be used again.
   - This is intentionally unsafe and useful for demonstrations.

Simple picture:

```text
Login -> AccessToken + RefreshToken
Use AccessToken for routes
AccessToken expires after 3 minutes
RefreshToken -> New AccessToken + New RefreshToken
Continue using protected routes
```

Protected routes include:

- `GET /admin/products`
- `POST /admin/products`
- `PUSH /admin/products`
- `DELETE /admin/products`
- `GET /user/products`
- SOAP operations like `ValidateToken`, `GetAccount`, `TransferFunds`, `SearchUser`, and `Logout`

All authentication events are logged in `/audit`.

The API logs:

- Successful login.
- Failed login.
- Missing access token.
- Valid access token.
- Invalid access token.
- Expired access token.
- Session cookie mismatch.
- Refresh token success.
- Refresh token failure.
- Refresh token reuse.
- Logout.

Important: the app does **not** log raw tokens. It logs token fingerprints, which are short SHA-256 hashes. This lets you trace a token safely without exposing the real token.

Read logs:

```bash
curl -s 'http://127.0.0.1:8089/audit'
```

Example auth log:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<response>
  <event>
    <type>auth</type>
    <event>refresh_token</event>
    <status>success</status>
    <username>admin_aurora</username>
    <role>admin</role>
    <session_id>session-id</session_id>
    <token_id>new-jwt-id</token_id>
    <details>
      <old_refresh_token_fingerprint>abc123...</old_refresh_token_fingerprint>
      <new_refresh_token_fingerprint>def456...</new_refresh_token_fingerprint>
      <refresh_rotated>False</refresh_rotated>
    </details>
  </event>
</response>
```

For fuzzing, this is useful because you can prove what happened:

- Did the scanner send no token?
- Did the JWT expire?
- Did the scanner detect that an old refresh token can be reused?
- Did a user token try an admin route?
- Did the refresh flow issue a new dynamic JWT?

---

## Refresh Token: Continuar Depois De 3 Minutos

Espere 3 minutos, ou continue usando a aplicacao ate o access token expirar.

Depois chame `RefreshToken`:

```bash
curl -s -X POST 'http://127.0.0.1:8089/soap' \
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

Na aplicacao vulneravel, a resposta entrega:

- Um novo `AccessToken`.
- Um novo `RefreshToken`.
- `Rotated` igual a `false`.

Agora use o novo `AccessToken`:

```bash
curl -s 'http://127.0.0.1:8089/admin/products' \
  -H 'Authorization: Bearer NEW_ACCESS_TOKEN'
```

Tente usar o refresh token antigo de novo. A aplicacao vulneravel aceita novamente. Isso e intencional e demonstra reuso de refresh token.

```text
refresh token reuse allowed
```

Isso prova que a rotacao do refresh token esta funcionando.

---

## Como A Autenticacao Funciona

O fluxo de autenticacao tem quatro pecas pequenas:

1. **Usuario e senha**
   - O usuario envia credenciais para a operacao SOAP `Login`.
   - Se estiver correto, a API cria uma sessao.

2. **Access token**
   - A API retorna um `AccessToken`.
   - Esse token e um JWT.
   - Ele e usado nas rotas protegidas com:

```text
Authorization: Bearer YOUR_ACCESS_TOKEN
```

3. **JWT dinamico**
   - O JWT e dinamico porque cada login e cada refresh cria um token novo.
   - Os campos `iat`, `exp` e `jti` mudam.
   - `iat` significa "emitido em".
   - `exp` significa "expira em".
   - `jti` e o id unico do token.
   - O access token expira depois de **3 minutos**.

4. **Refresh token**
   - Quando o access token expira, chame a operacao SOAP `RefreshToken`.
   - A aplicacao vulneravel retorna um novo access token e um novo refresh token.
   - O refresh token antigo nao pode ser usado novamente.
   - Isso se chama rotacao de refresh token.

Desenho simples:

```text
Login -> AccessToken + RefreshToken
Usa AccessToken nas rotas
AccessToken expira depois de 3 minutos
RefreshToken -> Novo AccessToken + Novo RefreshToken
Continua usando as rotas protegidas
```

Rotas protegidas incluem:

- `GET /admin/products`
- `POST /admin/products`
- `PUSH /admin/products`
- `DELETE /admin/products`
- `GET /user/products`
- Operacoes SOAP como `ValidateToken`, `GetAccount`, `TransferFunds`, `SearchUser` e `Logout`

Todos os eventos de autenticacao sao logados em `/audit`.

A API registra:

- Login com sucesso.
- Falha de login.
- Access token ausente.
- Access token valido.
- Access token invalido.
- Access token expirado.
- Cookie de sessao divergente.
- Refresh token com sucesso.
- Falha de refresh token.
- Reuso de refresh token.
- Logout.

Importante: a app **nao** grava tokens reais no log. Ela grava fingerprints dos tokens, que sao hashes SHA-256 curtos. Assim voce consegue rastrear o token sem expor o token verdadeiro.

Ler logs:

```bash
curl -s 'http://127.0.0.1:8089/audit'
```

Exemplo de log de autenticacao:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<response>
  <event>
    <type>auth</type>
    <event>refresh_token</event>
    <status>success</status>
    <username>admin_aurora</username>
    <role>admin</role>
    <session_id>session-id</session_id>
    <token_id>new-jwt-id</token_id>
    <details>
      <old_refresh_token_fingerprint>abc123...</old_refresh_token_fingerprint>
      <new_refresh_token_fingerprint>def456...</new_refresh_token_fingerprint>
      <refresh_rotated>False</refresh_rotated>
    </details>
  </event>
</response>
```

Para fuzzing, isso e util porque voce consegue provar o que aconteceu:

- O scanner mandou token vazio?
- O JWT expirou?
- O scanner reutilizou refresh token antigo?
- Um token de user tentou rota admin?
- O refresh emitiu um novo JWT dinamico?

---

## Admin Product Tests

Admins can list, create, edit, and delete products.

List:

```bash
curl -s 'http://127.0.0.1:8089/admin/products' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN'
```

Create:

```bash
curl -s -X POST 'http://127.0.0.1:8089/admin/products' \
  -H 'Content-Type: application/xml' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN' \
  --data '<product><sku>SKU-600</sku><name>Headset Prisma ANC</name><price>599.90</price><stock>14</stock></product>'
```

Edit with custom `PUSH`:

```bash
curl -s -X PUSH 'http://127.0.0.1:8089/admin/products' \
  -H 'Content-Type: application/xml' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN' \
  --data '<product><sku>SKU-600</sku><price>499.90</price><stock>20</stock></product>'
```

Delete:

```bash
curl -s -X DELETE 'http://127.0.0.1:8089/admin/products?sku=SKU-600' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN'
```

---

## Testes De Produto Como Admin

Admins podem listar, criar, editar e deletar produtos.

Listar:

```bash
curl -s 'http://127.0.0.1:8089/admin/products' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN'
```

Criar:

```bash
curl -s -X POST 'http://127.0.0.1:8089/admin/products' \
  -H 'Content-Type: application/xml' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN' \
  --data '<product><sku>SKU-600</sku><name>Headset Prisma ANC</name><price>599.90</price><stock>14</stock></product>'
```

Editar com verbo customizado `PUSH`:

```bash
curl -s -X PUSH 'http://127.0.0.1:8089/admin/products' \
  -H 'Content-Type: application/xml' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN' \
  --data '<product><sku>SKU-600</sku><price>499.90</price><stock>20</stock></product>'
```

Deletar:

```bash
curl -s -X DELETE 'http://127.0.0.1:8089/admin/products?sku=SKU-600' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN'
```

---

## User Product Tests

Users can only list products.

```bash
curl -s 'http://127.0.0.1:8089/user/products' \
  -H 'Authorization: Bearer USER_ACCESS_TOKEN'
```

If a user tries to create, edit, or delete, the app returns `403`.

```bash
curl -i -X POST 'http://127.0.0.1:8089/user/products' \
  -H 'Content-Type: application/xml' \
  -H 'Authorization: Bearer USER_ACCESS_TOKEN' \
  --data '<product><sku>SKU-700</sku><name>Blocked Product</name><price>10</price><stock>1</stock></product>'
```

---

## Testes De Produto Como User

Users so podem listar produtos.

```bash
curl -s 'http://127.0.0.1:8089/user/products' \
  -H 'Authorization: Bearer USER_ACCESS_TOKEN'
```

Se um user tentar criar, editar ou deletar, a aplicacao retorna `403`.

```bash
curl -i -X POST 'http://127.0.0.1:8089/user/products' \
  -H 'Content-Type: application/xml' \
  -H 'Authorization: Bearer USER_ACCESS_TOKEN' \
  --data '<product><sku>SKU-700</sku><name>Blocked Product</name><price>10</price><stock>1</stock></product>'
```

---

## Fuzzing Checklist

Use your DAST scanner like a curious child pressing buttons, but only in this lab.

Good fuzzing targets:

- `POST /soap` with `SOAPAction: Login`.
- `POST /soap` with `SOAPAction: RefreshToken`.
- `POST /soap` with `SOAPAction: ValidateToken`.
- `POST /soap` with `SOAPAction: SearchUser`.
- `GET /admin/products`.
- `POST /admin/products`.
- `PUSH /admin/products`.
- `DELETE /admin/products`.
- `GET /user/products`.
- `POST /user/products` to verify forbidden access.
- `TRACE /verbs` on the vulnerable app.

Authentication tests:

- Missing `Authorization` header.
- Invalid JWT.
- Expired JWT after 3 minutes.
- Modified JWT payload.
- Modified JWT signature.
- Old refresh token reuse.
- Missing refresh token rotation.
- Session cookie mismatch.
- User token trying admin path.
- Admin token using all verbs.

Vulnerable app tests on `8089`:

- `alg=none` JWT.
- Reusing refresh token.
- IDOR on account access.
- Unsafe XML reflection.
- `DOCTYPE` and `ENTITY` probes.
- `TRACE` reflection.

---

## Checklist De Fuzzing

Use seu scanner DAST como uma crianca curiosa apertando botoes, mas somente neste laboratorio.

Bons alvos de fuzzing:

- `POST /soap` com `SOAPAction: Login`.
- `POST /soap` com `SOAPAction: RefreshToken`.
- `POST /soap` com `SOAPAction: ValidateToken`.
- `POST /soap` com `SOAPAction: SearchUser`.
- `GET /admin/products`.
- `POST /admin/products`.
- `PUSH /admin/products`.
- `DELETE /admin/products`.
- `GET /user/products`.
- `POST /user/products` para validar acesso proibido.
- `TRACE /verbs` na aplicacao vulneravel.

Testes de autenticacao:

- Header `Authorization` ausente.
- JWT invalido.
- JWT expirado depois de 3 minutos.
- Payload do JWT alterado.
- Assinatura do JWT alterada.
- Reuso do refresh token antigo.
- Rotacao do refresh token.
- Cookie de sessao divergente.
- Token user tentando rota admin.
- Token admin usando todos os verbos.

Testes na aplicacao vulneravel em `8089`:

- JWT `alg=none`.
- Reuso de refresh token.
- IDOR em acesso de conta.
- Reflexao XML insegura.
- Probes `DOCTYPE` e `ENTITY`.
- Reflexao com `TRACE`.

---

## Build And Run On AWS ECS/Fargate

Think of ECS/Fargate like a cloud shelf that runs your container for you. You give AWS the image, the ports, CPU, memory, and networking.

Official AWS docs:

- Amazon ECR Docker push: https://docs.aws.amazon.com/AmazonECR/latest/userguide/docker-push-ecr-image.html
- Amazon ECS task definitions: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definitions.html
- Amazon ECS services: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs_services.html

This project includes:

- `deploy/aws/ecs-task-definition.json`
- `deploy/aws/create-ecs-fargate.sh`

The ECS version runs both apps inside the same Fargate task:

- Vulnerable app: container port `8089`
- Vulnerable app: container port `8089`

Before running the script, create or choose:

- A VPC.
- Two subnets.
- A Security Group allowing inbound `8089` and `8089` from your test IP.
- An IAM role named `ecsTaskExecutionRole`, or adjust the task definition.
- AWS CLI already logged in.
- Docker installed locally.

Set variables:

```bash
export AWS_REGION=us-east-1
export AWS_ACCOUNT_ID=123456789012
export SUBNETS=subnet-aaa111,subnet-bbb222
export SECURITY_GROUPS=sg-abc123
export PUBLIC_HOST=your-public-dns-or-load-balancer
```

Run:

```bash
chmod +x deploy/aws/create-ecs-fargate.sh
./deploy/aws/create-ecs-fargate.sh
```

Test after the ECS task is reachable:

```text
http://YOUR_ECS_PUBLIC_ENDPOINT:8089/soap?wsdl
http://YOUR_ECS_PUBLIC_ENDPOINT:8089/soap?wsdl
```

For a cleaner architecture, place an Application Load Balancer in front of ECS and expose:

- Listener/rule for the vulnerable service on `8089`.
- Listener/rule for the vulnerable service on `8089`.

For demos, direct public Fargate networking is enough if your Security Group is restricted to your testing IP.

---

## Build E Execucao Na AWS ECS/Fargate

Pense no ECS/Fargate como uma prateleira na nuvem que roda seu container para voce. Voce entrega para a AWS a imagem, portas, CPU, memoria e rede.

Documentacao oficial AWS:

- Push Docker no Amazon ECR: https://docs.aws.amazon.com/AmazonECR/latest/userguide/docker-push-ecr-image.html
- Task definitions do Amazon ECS: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definitions.html
- Services do Amazon ECS: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs_services.html

Este projeto inclui:

- `deploy/aws/ecs-task-definition.json`
- `deploy/aws/create-ecs-fargate.sh`

A versao ECS roda as duas aplicacoes dentro do mesmo task Fargate:

- App vulneravel: porta de container `8089`
- App vulneravel: porta de container `8089`

Antes de rodar o script, crie ou escolha:

- Uma VPC.
- Duas subnets.
- Um Security Group permitindo entrada nas portas `8089` e `8089` somente do seu IP de teste.
- Uma role IAM chamada `ecsTaskExecutionRole`, ou ajuste a task definition.
- AWS CLI ja autenticado.
- Docker instalado localmente.

Defina variaveis:

```bash
export AWS_REGION=us-east-1
export AWS_ACCOUNT_ID=123456789012
export SUBNETS=subnet-aaa111,subnet-bbb222
export SECURITY_GROUPS=sg-abc123
export PUBLIC_HOST=seu-dns-publico-ou-load-balancer
```

Rode:

```bash
chmod +x deploy/aws/create-ecs-fargate.sh
./deploy/aws/create-ecs-fargate.sh
```

Teste quando o task ECS estiver acessivel:

```text
http://YOUR_ECS_PUBLIC_ENDPOINT:8089/soap?wsdl
http://YOUR_ECS_PUBLIC_ENDPOINT:8089/soap?wsdl
```

Para uma arquitetura mais organizada, coloque um Application Load Balancer na frente do ECS e exponha:

- Listener/regra para a aplicacao vulneravel na `8089`.
- Listener/regra para a aplicacao vulneravel na `8089`.

Para demonstracoes, rede publica direta no Fargate e suficiente se o Security Group estiver restrito ao seu IP de teste.

---

## Build And Run On Azure Container Apps

Azure Container Apps is easiest when each public app has one HTTP ingress. So this project uses the same image twice:

- One Container App with `APP_MODE=vulnerable`.

Official Microsoft docs:

- Azure Container Registry Docker push: https://learn.microsoft.com/azure/container-registry/container-registry-get-started-docker-cli
- Azure Container Apps ingress: https://learn.microsoft.com/azure/container-apps/ingress-overview
- Azure Container Apps create command: https://learn.microsoft.com/cli/azure/containerapp

This project includes:

- `deploy/azure/create-container-apps.sh`
- `deploy/azure/container-app-vulnerable.yaml`

Before running the script, install and login:

```bash
az login
az extension add --name containerapp --upgrade
```

Choose a globally unique ACR name. It must be lowercase letters and numbers.

```bash
export LOCATION=eastus
export RESOURCE_GROUP=rg-soap-dast-lab
export ENVIRONMENT_NAME=cae-soap-dast-lab
export ACR_NAME=youruniqueacrname
```

Run:

```bash
chmod +x deploy/azure/create-container-apps.sh
./deploy/azure/create-container-apps.sh
```

The script creates two URLs:

```text
https://soap-dast-lab-vulnerable.YOUR_ENV.azurecontainerapps.io/soap?wsdl
```

Use the vulnerable URL for attack demonstrations.

---

## Build E Execucao No Azure Container Apps

Azure Container Apps fica mais simples quando cada app publico tem um ingress HTTP principal. Por isso este projeto usa a mesma imagem duas vezes:

- Um Container App com `APP_MODE=vulnerable`.

Documentacao oficial Microsoft:

- Push Docker no Azure Container Registry: https://learn.microsoft.com/azure/container-registry/container-registry-get-started-docker-cli
- Ingress no Azure Container Apps: https://learn.microsoft.com/azure/container-apps/ingress-overview
- Comando de criacao do Azure Container Apps: https://learn.microsoft.com/cli/azure/containerapp

Este projeto inclui:

- `deploy/azure/create-container-apps.sh`
- `deploy/azure/container-app-vulnerable.yaml`

Antes de rodar o script, instale e autentique:

```bash
az login
az extension add --name containerapp --upgrade
```

Escolha um nome de ACR globalmente unico. Ele deve ter letras minusculas e numeros.

```bash
export LOCATION=eastus
export RESOURCE_GROUP=rg-soap-dast-lab
export ENVIRONMENT_NAME=cae-soap-dast-lab
export ACR_NAME=seuacrnomeunico
```

Rode:

```bash
chmod +x deploy/azure/create-container-apps.sh
./deploy/azure/create-container-apps.sh
```

O script cria duas URLs:

```text
https://soap-dast-lab-vulnerable.YOUR_ENV.azurecontainerapps.io/soap?wsdl
```

Use a URL vulneravel para demonstracoes de ataque.

---

## Safety Note

Run this only in environments you own or are allowed to test. The vulnerable server is intentionally unsafe.

## Nota De Seguranca

Rode isso somente em ambientes seus ou onde voce tem autorizacao para testar. O servidor vulneravel e inseguro de proposito.
