# SOAP DAST Lab

English | Portugues

This project is a small security testing playground. Think of it like a toy store with two doors:

- Door 1, port `8088`: the safer SOAP API.
- Door 2, port `8089`: the intentionally vulnerable SOAP API.

You use it to test DAST scanners, fuzzing, JWT login, refresh tokens, session cookies, HTTP verbs, admin routes, and user routes.

Este projeto e um pequeno laboratorio para testes de seguranca. Pense nele como uma lojinha com duas portas:

- Porta 1, porta `8088`: API SOAP mais segura/controlada.
- Porta 2, porta `8089`: API SOAP vulneravel de proposito.

Voce usa para testar scanners DAST, fuzzing, login JWT, refresh token, cookie de sessao, verbos HTTP, rotas de admin e rotas de user.

---

## What Was Built

The container starts two Python applications at the same time:

- `server.py`: secure/control version on `8088`.
- `vulnerable_server.py`: intentionally vulnerable version on `8089`.

Both applications support:

- SOAP login with JWT.
- Dynamic JWT access tokens.
- Access token expiration after **3 minutes**.
- Refresh token flow to continue the session.
- Session cookie named `DASTSESSION`.
- Ten users at the same time.
- Five admin users.
- Five normal users.
- Product routes for testing HTTP verbs.

The secure app allows:

- Admins: `GET`, `POST`, `PUSH`, `DELETE`.
- Users: only `GET`.

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

O container inicia duas aplicacoes Python ao mesmo tempo:

- `server.py`: versao segura/controlada na porta `8088`.
- `vulnerable_server.py`: versao vulneravel de proposito na porta `8089`.

As duas aplicacoes suportam:

- Login SOAP com JWT.
- Token JWT dinamico.
- Access token expira depois de **3 minutos**.
- Refresh token para continuar a sessao.
- Cookie de sessao chamado `DASTSESSION`.
- Dez usuarios autenticados ao mesmo tempo.
- Cinco usuarios admin.
- Cinco usuarios comuns.
- Rotas de produtos para testar verbos HTTP.

A aplicacao segura permite:

- Admins: `GET`, `POST`, `PUSH`, `DELETE`.
- Users: somente `GET`.

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

- `server.py`: secure SOAP/API server.
- `vulnerable_server.py`: vulnerable SOAP/API server.
- `run_both.py`: starts both servers inside one container.
- `Dockerfile`: builds the container image.
- `docker-compose.yml`: runs both apps locally.
- `deploy/aws/ecs-task-definition.json`: AWS ECS/Fargate task definition example.
- `deploy/aws/create-ecs-fargate.sh`: helper script to build, push to ECR, and create an ECS service.
- `deploy/azure/create-container-apps.sh`: helper script to build, push to ACR, and create Azure Container Apps.
- `deploy/azure/container-app-safe.yaml`: Azure Container Apps YAML for the safe app.
- `deploy/azure/container-app-vulnerable.yaml`: Azure Container Apps YAML for the vulnerable app.
- `requests.http`: SOAP examples.
- `vulnerable-requests.http`: vulnerable examples.
- `admin-user-requests.http`: admin/user product route examples.

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

Imagine Docker is a lunchbox. We put both apps inside the lunchbox and open two little windows: `8088` and `8089`.

Build and start:

```bash
docker compose up --build -d
```

Check if it is running:

```bash
docker compose ps
```

Open the safe WSDL:

```text
http://127.0.0.1:8088/soap?wsdl
```

Open the vulnerable WSDL:

```text
http://127.0.0.1:8089/soap?wsdl
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

Imagine que o Docker e uma lancheira. Colocamos as duas aplicacoes dentro da lancheira e abrimos duas janelinhas: `8088` e `8089`.

Build e start:

```bash
docker compose up --build -d
```

Ver se esta rodando:

```bash
docker compose ps
```

Abrir o WSDL seguro:

```text
http://127.0.0.1:8088/soap?wsdl
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

## Login: Get Access Token And Refresh Token

The access token is like a small visitor badge. It works for 3 minutes.

The refresh token is like asking the front desk: "Please give me a new badge so I can continue."

Admin login:

```bash
curl -s -X POST 'http://127.0.0.1:8088/soap' \
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
curl -s 'http://127.0.0.1:8088/admin/products' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

---

## Login: Pegar Access Token E Refresh Token

O access token e como um cracha pequeno. Ele funciona por 3 minutos.

O refresh token e como falar na recepcao: "Me da outro cracha para eu continuar."

Login admin:

```bash
curl -s -X POST 'http://127.0.0.1:8088/soap' \
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
curl -s 'http://127.0.0.1:8088/admin/products' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```

---

## Refresh Token: Continue After 3 Minutes

Wait 3 minutes, or keep using the app until the access token expires.

Then call `RefreshToken`:

```bash
curl -s -X POST 'http://127.0.0.1:8088/soap' \
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

In the secure app, the response gives you:

- A new `AccessToken`.
- A new `RefreshToken`.
- `Rotated` equals `true`.

Now use the new `AccessToken`:

```bash
curl -s 'http://127.0.0.1:8088/admin/products' \
  -H 'Authorization: Bearer NEW_ACCESS_TOKEN'
```

Try the old refresh token again. The secure app should reject it with:

```text
refresh_token_reused
```

That proves the refresh token rotation is working.

---

## Refresh Token: Continuar Depois De 3 Minutos

Espere 3 minutos, ou continue usando a aplicacao ate o access token expirar.

Depois chame `RefreshToken`:

```bash
curl -s -X POST 'http://127.0.0.1:8088/soap' \
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

Na aplicacao segura, a resposta entrega:

- Um novo `AccessToken`.
- Um novo `RefreshToken`.
- `Rotated` igual a `true`.

Agora use o novo `AccessToken`:

```bash
curl -s 'http://127.0.0.1:8088/admin/products' \
  -H 'Authorization: Bearer NEW_ACCESS_TOKEN'
```

Tente usar o refresh token antigo de novo. A aplicacao segura deve rejeitar com:

```text
refresh_token_reused
```

Isso prova que a rotacao do refresh token esta funcionando.

---

## Admin Product Tests

Admins can list, create, edit, and delete products.

List:

```bash
curl -s 'http://127.0.0.1:8088/admin/products' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN'
```

Create:

```bash
curl -s -X POST 'http://127.0.0.1:8088/admin/products' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN' \
  --data '{"sku":"SKU-600","name":"Headset Prisma ANC","price":599.90,"stock":14}'
```

Edit with custom `PUSH`:

```bash
curl -s -X PUSH 'http://127.0.0.1:8088/admin/products' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN' \
  --data '{"sku":"SKU-600","price":499.90,"stock":20}'
```

Delete:

```bash
curl -s -X DELETE 'http://127.0.0.1:8088/admin/products?sku=SKU-600' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN'
```

---

## Testes De Produto Como Admin

Admins podem listar, criar, editar e deletar produtos.

Listar:

```bash
curl -s 'http://127.0.0.1:8088/admin/products' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN'
```

Criar:

```bash
curl -s -X POST 'http://127.0.0.1:8088/admin/products' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN' \
  --data '{"sku":"SKU-600","name":"Headset Prisma ANC","price":599.90,"stock":14}'
```

Editar com verbo customizado `PUSH`:

```bash
curl -s -X PUSH 'http://127.0.0.1:8088/admin/products' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN' \
  --data '{"sku":"SKU-600","price":499.90,"stock":20}'
```

Deletar:

```bash
curl -s -X DELETE 'http://127.0.0.1:8088/admin/products?sku=SKU-600' \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN'
```

---

## User Product Tests

Users can only list products.

```bash
curl -s 'http://127.0.0.1:8088/user/products' \
  -H 'Authorization: Bearer USER_ACCESS_TOKEN'
```

If a user tries to create, edit, or delete, the app returns `403`.

```bash
curl -i -X POST 'http://127.0.0.1:8088/user/products' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer USER_ACCESS_TOKEN' \
  --data '{"sku":"SKU-700","name":"Blocked Product","price":10,"stock":1}'
```

---

## Testes De Produto Como User

Users so podem listar produtos.

```bash
curl -s 'http://127.0.0.1:8088/user/products' \
  -H 'Authorization: Bearer USER_ACCESS_TOKEN'
```

Se um user tentar criar, editar ou deletar, a aplicacao retorna `403`.

```bash
curl -i -X POST 'http://127.0.0.1:8088/user/products' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer USER_ACCESS_TOKEN' \
  --data '{"sku":"SKU-700","name":"Blocked Product","price":10,"stock":1}'
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
- Refresh token rotation.
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

- Safe app: container port `8088`
- Vulnerable app: container port `8089`

Before running the script, create or choose:

- A VPC.
- Two subnets.
- A Security Group allowing inbound `8088` and `8089` from your test IP.
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
http://YOUR_ECS_PUBLIC_ENDPOINT:8088/soap?wsdl
http://YOUR_ECS_PUBLIC_ENDPOINT:8089/soap?wsdl
```

For a cleaner architecture, place an Application Load Balancer in front of ECS and expose:

- Listener/rule for the safe service on `8088`.
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

- App segura: porta de container `8088`
- App vulneravel: porta de container `8089`

Antes de rodar o script, crie ou escolha:

- Uma VPC.
- Duas subnets.
- Um Security Group permitindo entrada nas portas `8088` e `8089` somente do seu IP de teste.
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
http://YOUR_ECS_PUBLIC_ENDPOINT:8088/soap?wsdl
http://YOUR_ECS_PUBLIC_ENDPOINT:8089/soap?wsdl
```

Para uma arquitetura mais organizada, coloque um Application Load Balancer na frente do ECS e exponha:

- Listener/regra para a aplicacao segura na `8088`.
- Listener/regra para a aplicacao vulneravel na `8089`.

Para demonstracoes, rede publica direta no Fargate e suficiente se o Security Group estiver restrito ao seu IP de teste.

---

## Build And Run On Azure Container Apps

Azure Container Apps is easiest when each public app has one HTTP ingress. So this project uses the same image twice:

- One Container App with `APP_MODE=safe`.
- One Container App with `APP_MODE=vulnerable`.

Official Microsoft docs:

- Azure Container Registry Docker push: https://learn.microsoft.com/azure/container-registry/container-registry-get-started-docker-cli
- Azure Container Apps ingress: https://learn.microsoft.com/azure/container-apps/ingress-overview
- Azure Container Apps create command: https://learn.microsoft.com/cli/azure/containerapp

This project includes:

- `deploy/azure/create-container-apps.sh`
- `deploy/azure/container-app-safe.yaml`
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
https://soap-dast-lab-safe.YOUR_ENV.azurecontainerapps.io/soap?wsdl
https://soap-dast-lab-vulnerable.YOUR_ENV.azurecontainerapps.io/soap?wsdl
```

Use the safe URL for normal authentication and refresh token demos.

Use the vulnerable URL for attack demonstrations.

---

## Build E Execucao No Azure Container Apps

Azure Container Apps fica mais simples quando cada app publico tem um ingress HTTP principal. Por isso este projeto usa a mesma imagem duas vezes:

- Um Container App com `APP_MODE=safe`.
- Um Container App com `APP_MODE=vulnerable`.

Documentacao oficial Microsoft:

- Push Docker no Azure Container Registry: https://learn.microsoft.com/azure/container-registry/container-registry-get-started-docker-cli
- Ingress no Azure Container Apps: https://learn.microsoft.com/azure/container-apps/ingress-overview
- Comando de criacao do Azure Container Apps: https://learn.microsoft.com/cli/azure/containerapp

Este projeto inclui:

- `deploy/azure/create-container-apps.sh`
- `deploy/azure/container-app-safe.yaml`
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
https://soap-dast-lab-safe.YOUR_ENV.azurecontainerapps.io/soap?wsdl
https://soap-dast-lab-vulnerable.YOUR_ENV.azurecontainerapps.io/soap?wsdl
```

Use a URL segura para demonstracoes normais de autenticacao e refresh token.

Use a URL vulneravel para demonstracoes de ataque.

---

## Safety Note

Run this only in environments you own or are allowed to test. The vulnerable server is intentionally unsafe.

## Nota De Seguranca

Rode isso somente em ambientes seus ou onde voce tem autorizacao para testar. O servidor vulneravel e inseguro de proposito.
