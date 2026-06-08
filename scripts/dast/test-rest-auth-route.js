#!/usr/bin/env node

const baseUrl = process.env.REST_BASE_URL || "https://ca-rest-soap-labs.wonderfulcoast-2578bc9b.eastus.azurecontainerapps.io";
const username = process.env.REST_USERNAME || "admin_aurora";
const password = process.env.REST_PASSWORD || "adminpass1";

async function postJson(path, body, headers = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json",
      ...headers,
    },
    body: JSON.stringify(body),
  });
  return { status: response.status, json: await response.json() };
}

async function getJson(path, headers = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "GET",
    headers: {
      "Accept": "application/json",
      ...headers,
    },
  });
  return { status: response.status, json: await response.json() };
}

function requireStatus(step, result, expectedStatus) {
  console.log(`${step}: HTTP ${result.status}`);
  if (result.status !== expectedStatus) {
    console.log(JSON.stringify(result.json, null, 2));
    throw new Error(`${step} expected HTTP ${expectedStatus}, got HTTP ${result.status}`);
  }
}

async function main() {
  console.log(`Base URL: ${baseUrl}`);

  const login = await postJson("/api/login", { username, password });
  requireStatus("POST /api/login", login, 200);
  const accessToken = login.json.accessToken;
  const refreshToken = login.json.refreshToken;
  if (!accessToken || !refreshToken) {
    throw new Error("Login did not return accessToken and refreshToken.");
  }
  console.log("Login tokens extracted.");

  const refresh = await postJson("/api/refresh", { refreshToken });
  requireStatus("POST /api/refresh", refresh, 200);
  const refreshedAccessToken = refresh.json.accessToken;
  if (!refreshedAccessToken) {
    throw new Error("Refresh did not return a new accessToken.");
  }
  console.log("Refresh token flow returned an access token.");

  const validate = await getJson("/api/validate", {
    "Authorization": `Bearer ${refreshedAccessToken}`,
  });
  requireStatus("GET /api/validate", validate, 200);
  if (!validate.json.subject) {
    throw new Error("Validate did not return subject.");
  }
  console.log(`Validated subject: ${validate.json.subject}`);

  const products = await getJson("/api/admin/products", {
    "Authorization": `Bearer ${refreshedAccessToken}`,
  });
  requireStatus("GET /api/admin/products", products, 200);
  console.log("Authenticated REST route consumed successfully.");
}

main().catch((error) => {
  console.error(`FAILED: ${error.message}`);
  process.exit(1);
});
