#!/usr/bin/env node

const baseUrl = process.env.SOAP_BASE_URL || "http://127.0.0.1:8099";
const username = process.env.SOAP_USERNAME || "admin_aurora";
const password = process.env.SOAP_PASSWORD || "adminpass1";

function tagValue(xml, tagName) {
  const pattern = new RegExp(`<(?:[A-Za-z0-9_]+:)?${tagName}(?:\\s[^>]*)?>([\\s\\S]*?)</(?:[A-Za-z0-9_]+:)?${tagName}>`, "i");
  const match = xml.match(pattern);
  return match ? match[1].trim() : null;
}

async function soap(path, action, body, headers = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/xml",
      "SOAPAction": action,
      ...headers,
    },
    body,
  });
  return { status: response.status, text: await response.text() };
}

function loginEnvelope() {
  return `<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:lab="urn:soap-dast-lab">
  <soap:Body>
    <lab:Login>
      <lab:Username>${username}</lab:Username>
      <lab:Password>${password}</lab:Password>
    </lab:Login>
  </soap:Body>
</soap:Envelope>`;
}

function refreshEnvelope(refreshToken) {
  return `<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:lab="urn:soap-dast-lab">
  <soap:Body>
    <lab:RefreshToken>${refreshToken}</lab:RefreshToken>
  </soap:Body>
</soap:Envelope>`;
}

function validateEnvelope() {
  return `<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:lab="urn:soap-dast-lab">
  <soap:Body>
    <lab:ValidateToken/>
  </soap:Body>
</soap:Envelope>`;
}

function requireStatus(step, result, expectedStatus) {
  console.log(`${step}: HTTP ${result.status}`);
  if (result.status !== expectedStatus) {
    console.log(result.text);
    throw new Error(`${step} expected HTTP ${expectedStatus}, got HTTP ${result.status}`);
  }
}

async function main() {
  console.log(`Base URL: ${baseUrl}`);

  const login = await soap("/soap/auth", "Login", loginEnvelope());
  requireStatus("POST /soap/auth SOAPAction Login", login, 200);
  const accessToken = tagValue(login.text, "AccessToken");
  const refreshToken = tagValue(login.text, "RefreshToken");
  if (!accessToken || !refreshToken) {
    throw new Error("Login did not return AccessToken and RefreshToken.");
  }
  console.log("Login tokens extracted.");

  const refresh = await soap("/soap/refreshtoken", "RefreshToken", refreshEnvelope(refreshToken));
  requireStatus("POST /soap/refreshtoken SOAPAction RefreshToken", refresh, 200);
  const refreshedAccessToken = tagValue(refresh.text, "AccessToken");
  if (!refreshedAccessToken) {
    throw new Error("RefreshToken did not return a new AccessToken.");
  }
  console.log("Refresh token flow returned an access token.");

  const validate = await soap("/soap/auth", "ValidateToken", validateEnvelope(), {
    "Authorization": `Bearer ${refreshedAccessToken}`,
  });
  requireStatus("POST /soap/auth SOAPAction ValidateToken", validate, 200);
  console.log("Refreshed access token validated on /soap/auth.");

  const audit = await fetch(`${baseUrl}/audit`);
  const auditText = await audit.text();
  console.log(`GET /audit: HTTP ${audit.status}`);
  if (!auditText.includes("lab_login") && !auditText.includes("login")) {
    throw new Error("Audit log does not include login events.");
  }
  if (!auditText.includes("lab_refresh_token") && !auditText.includes("refresh_token")) {
    throw new Error("Audit log does not include refresh token events.");
  }
  if (!auditText.includes("interaction")) {
    throw new Error("Audit log does not include interaction events.");
  }

  console.log("Audit contains login, refresh, and interaction events.");

  const tracking = await fetch(`${baseUrl}/login-tracking?limit=100`);
  const trackingText = await tracking.text();
  console.log(`GET /login-tracking: HTTP ${tracking.status}`);
  if (!trackingText.includes("login_attempts")) {
    throw new Error("Login tracking does not include login_attempts summary.");
  }
  if (!trackingText.includes("refresh_token_requests")) {
    throw new Error("Login tracking does not include refresh_token_requests summary.");
  }
  if (!trackingText.includes("token_validation_events")) {
    throw new Error("Login tracking does not include token_validation_events summary.");
  }

  console.log("Login tracking contains login, refresh, and token validation evidence.");
  console.log("OK: /soap/auth login/validation and /soap/refreshtoken refresh routes are working.");
}

main().catch((error) => {
  console.error(`FAILED: ${error.message}`);
  process.exit(1);
});
