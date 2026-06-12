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
        throw "REST Login failed. Expected /api/login.";
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
    var tokenRequest = httpClient.createRequest(getLoginUrl());
    tokenRequest.addHeader("Content-Type", "application/json");
    tokenRequest.addHeader("Accept", "application/json");
    tokenRequest.setMethod("POST");
    tokenRequest.setBody("{\"username\":\"" + escapeJson(username) + "\",\"password\":\"" + escapeJson(password) + "\"}");
    return tokenRequest;
}

function createRefreshTokenRequest(currentRefreshToken) {
    var tokenRequest = httpClient.createRequest(getRefreshUrl());
    tokenRequest.addHeader("Content-Type", "application/json");
    tokenRequest.addHeader("Accept", "application/json");
    if (bearerToken !== null && bearerToken !== "") {
        tokenRequest.addHeader("Authorization", "Bearer " + bearerToken);
    }
    tokenRequest.setMethod("POST");
    tokenRequest.setBody("{\"refreshToken\":\"" + escapeJson(currentRefreshToken) + "\"}");
    return tokenRequest;
}

function fetchToken(tokenRequest, actionName, throwOnFailure) {
    var response = tokenRequest.send();
    var responseBody = response.asString();
    var tokenData = parseJson(responseBody);

    if (tokenData === null || tokenData.accessToken === null || tokenData.accessToken === "" || tokenData.expiresAt === null || tokenData.expiresAt === "") {
        if (throwOnFailure === true) {
            throw "REST " + actionName + " failed. Response: " + responseBody;
        }
        return null;
    }

    return {
        accessToken: tokenData.accessToken,
        refreshToken: tokenData.refreshToken,
        expiresAt: parseInt(tokenData.expiresAt, 10) * 1000
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

function getLoginUrl() {
    var configuredUrl = getVariableOrDefault("loginBaseUrl", "");
    if (configuredUrl !== "") {
        return normalizeRestUrl(configuredUrl, "/api/login");
    }
    return "https://ca-rest-soap-labs.wonderfulcoast-2578bc9b.eastus.azurecontainerapps.io/api/login";
}

function getRefreshUrl() {
    var configuredUrl = getVariableOrDefault("refreshBaseUrl", "");
    if (configuredUrl !== "") {
        return normalizeRestUrl(configuredUrl, "/api/refresh");
    }
    return replaceLastPath(getLoginUrl(), "/api/refresh");
}

function normalizeRestUrl(url, expectedPath) {
    var normalized = trimValue(url).replace(/\/$/, "");
    if (normalized.match(/\/api\/login$/i) || normalized.match(/\/api\/refresh$/i) || normalized.match(/\/api\/validate$/i)) {
        return replaceLastPath(normalized, expectedPath);
    }
    if (normalized.match(/\/api$/i)) {
        return normalized + expectedPath.replace(/^\/api/, "");
    }
    return normalized + expectedPath;
}

function replaceLastPath(url, expectedPath) {
    return url
        .replace(/\/api\/login$/i, expectedPath)
        .replace(/\/api\/refresh$/i, expectedPath)
        .replace(/\/api\/validate$/i, expectedPath);
}

function getVariableOrDefault(name, fallback) {
    var value = vc.variables[name];
    if (value === null || value === undefined || trimValue(String(value)) === "") {
        return fallback;
    }
    return trimValue(String(value));
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

function parseJson(jsonText) {
    try {
        return JSON.parse(jsonText);
    } catch (e) {
        return null;
    }
}

function trimValue(value) {
    return value.replace(/^\s+|\s+$/g, "");
}

function escapeJson(value) {
    return String(value)
        .replace(/\\/g, "\\\\")
        .replace(/"/g, "\\\"")
        .replace(/\r/g, "\\r")
        .replace(/\n/g, "\\n");
}
