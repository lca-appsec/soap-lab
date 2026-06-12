var bearerToken = null;
var refreshToken = null;
var tokenExpiresAt = null;

var defaultUsername = "veracode";
var defaultPassword = "veracode";

function run() {
    if (bearerToken === null || bearerToken === "" || tokenExpiresAt === null) {
        authenticateWithLogin();
    } else if (isTokenExpired()) {
        reauthenticateWithRefreshToken();
    }

    if (bearerToken === null || bearerToken === "") {
        authenticateWithLogin();
    }

    updateRequestHeaders(bearerToken);
}

function authenticateWithLogin() {
    var username = getVariableOrDefault("testUsername", defaultUsername);
    var password = getVariableOrDefault("testPassword", defaultPassword);
    var tokenData = fetchToken(createLoginRequest(username, password), "Login", false);

    if (tokenData === null && (username !== defaultUsername || password !== defaultPassword)) {
        tokenData = fetchToken(createLoginRequest(defaultUsername, defaultPassword), "LoginDefaultFallback", false);
    }

    if (tokenData === null) {
        throw "SOAP Login failed. Expected /soap/auth with SOAPAction Login.";
    }

    bearerToken = tokenData.accessToken;
    refreshToken = normalizeRefreshTokenValue(tokenData.refreshToken);
    tokenExpiresAt = tokenData.expiresAt;
}

function reauthenticateWithRefreshToken() {
    var usableRefreshToken = normalizeRefreshTokenValue(refreshToken);
    if (usableRefreshToken === "") {
        authenticateWithLogin();
        return;
    }

    var tokenData = fetchToken(createRefreshTokenRequest(usableRefreshToken), "RefreshToken", false);
    if (tokenData === null) {
        bearerToken = null;
        refreshToken = null;
        tokenExpiresAt = null;
        authenticateWithLogin();
        return;
    }

    bearerToken = tokenData.accessToken;
    refreshToken = normalizeRefreshTokenValue(tokenData.refreshToken) || usableRefreshToken;
    tokenExpiresAt = tokenData.expiresAt;
}

function createLoginRequest(username, password) {
    var tokenRequest = httpClient.createRequest(getAuthUrl());
    tokenRequest.addHeader("Content-Type", "application/xml");
    tokenRequest.addHeader("SOAPAction", "Login");
    tokenRequest.setMethod("POST");
    tokenRequest.setBody("<?xml version=\"1.0\"?>\r\n" +
        "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:lab=\"urn:soap-dast-lab\">\r\n" +
        "  <soap:Body>\r\n" +
        "    <lab:Login>\r\n" +
        "      <lab:Username>" + escapeXml(username) + "</lab:Username>\r\n" +
        "      <lab:Password>" + escapeXml(password) + "</lab:Password>\r\n" +
        "    </lab:Login>\r\n" +
        "  </soap:Body>\r\n" +
        "</soap:Envelope>");
    return tokenRequest;
}

function createRefreshTokenRequest(currentRefreshToken) {
    var tokenRequest = httpClient.createRequest(getRefreshUrl());
    tokenRequest.addHeader("Content-Type", "application/xml");
    tokenRequest.addHeader("SOAPAction", "RefreshToken");
    if (bearerToken !== null && bearerToken !== "") {
        tokenRequest.addHeader("Authorization", "Bearer " + bearerToken);
    }
    tokenRequest.setMethod("POST");
    tokenRequest.setBody("<?xml version=\"1.0\"?>\r\n" +
        "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:lab=\"urn:soap-dast-lab\">\r\n" +
        "  <soap:Body>\r\n" +
        "    <lab:RefreshToken>" + escapeXml(currentRefreshToken) + "</lab:RefreshToken>\r\n" +
        "  </soap:Body>\r\n" +
        "</soap:Envelope>");
    return tokenRequest;
}

function fetchToken(tokenRequest, actionName, throwOnFailure) {
    var response = tokenRequest.send();
    var responseBody = response.asString();
    var accessToken = getXmlTagValue(responseBody, "AccessToken");
    var newRefreshToken = getXmlTagValue(responseBody, "RefreshToken");
    var expiresAt = getXmlTagValue(responseBody, "ExpiresAt");

    if (accessToken === null || accessToken === "" || expiresAt === null || expiresAt === "") {
        if (throwOnFailure === true) {
            throw "SOAP " + actionName + " failed. Response: " + responseBody;
        }
        return null;
    }

    return {
        accessToken: accessToken,
        refreshToken: newRefreshToken,
        expiresAt: parseInt(expiresAt, 10) * 1000
    };
}

function isTokenExpired() {
    if (tokenExpiresAt === null) {
        return true;
    }
    return new Date().getTime() >= (tokenExpiresAt - 30000);
}

function updateRequestHeaders(token) {
    request.addHeader("Authorization", "Bearer " + token);
}

function getAuthUrl() {
    var configuredUrl = getVariableOrDefault("loginBaseUrl", "");
    if (configuredUrl !== "") {
        return normalizeSoapAuthUrl(configuredUrl);
    }
    return "https://ca-rest-soap-labs.wonderfulcoast-2578bc9b.eastus.azurecontainerapps.io/soap/auth";
}

function getRefreshUrl() {
    var configuredUrl = getVariableOrDefault("refreshBaseUrl", "");
    if (configuredUrl !== "") {
        return normalizeSoapRefreshUrl(configuredUrl);
    }
    return normalizeSoapRefreshUrl(getAuthUrl());
}

function normalizeSoapAuthUrl(url) {
    var normalized = trimValue(url).replace(/\/$/, "");
    if (normalized.match(/\/soap\/auth$/i)) {
        return normalized;
    }
    if (normalized.match(/\/soap\/refreshtoken$/i)) {
        return normalized.replace(/\/soap\/refreshtoken$/i, "/soap/auth");
    }
    if (normalized.match(/\/soap$/i)) {
        return normalized.replace(/\/soap$/i, "/soap/auth");
    }
    return normalized + "/soap/auth";
}

function normalizeSoapRefreshUrl(url) {
    var normalized = trimValue(url).replace(/\/$/, "");
    if (normalized.match(/\/soap\/refreshtoken$/i)) {
        return normalized;
    }
    if (normalized.match(/\/soap\/auth$/i)) {
        return normalized.replace(/\/soap\/auth$/i, "/soap/refreshtoken");
    }
    if (normalized.match(/\/soap$/i)) {
        return normalized.replace(/\/soap$/i, "/soap/refreshtoken");
    }
    return normalized + "/soap/refreshtoken";
}

function getVariableOrDefault(name, fallback) {
    var value = vc.variables[name];
    if (value === null || value === undefined || trimValue(String(value)) === "") {
        return fallback;
    }
    return trimValue(String(value));
}

function getXmlTagValue(xml, tagName) {
    var regex = new RegExp("<(?:[A-Za-z0-9_]+:)?" + tagName + "(?:\\s[^>]*)?>([\\s\\S]*?)</(?:[A-Za-z0-9_]+:)?" + tagName + ">", "i");
    var match = regex.exec(xml);
    if (match === null || match.length < 2) {
        return null;
    }
    return trimValue(match[1]);
}

function normalizeRefreshTokenValue(value) {
    if (value === null || value === undefined) {
        return "";
    }
    var normalized = trimValue(String(value));
    var upper = normalized.toUpperCase();
    if (normalized === "" || upper === "[REDACTED]" || upper === "REDACTED" || upper === "NULL" || upper === "UNDEFINED" || upper === "YOUR_REFRESH_TOKEN") {
        return "";
    }
    return normalized;
}

function trimValue(value) {
    return value.replace(/^\s+|\s+$/g, "");
}

function escapeXml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&apos;");
}
