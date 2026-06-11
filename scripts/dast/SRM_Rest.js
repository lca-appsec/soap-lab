var bearerToken = null;
var refreshToken = null;
var tokenExpiresAt = null;
var defaultUsername = "admin_aurora";
var defaultPassword = "adminpass1";

function run() {
    if (bearerToken === null) {
        authenticateWithLogin();
    } else if (isTokenExpired()) {
        reauthenticateWithRefreshToken();
    }

    if (bearerToken === null || bearerToken === "") {
        authenticateWithLogin();
    }

    updateRequestHeaders(bearerToken);
    updateCurrentRefreshRequestBodyIfNeeded();
}

function authenticateWithLogin() {
    var username = getVariableOrDefault("testUsername", defaultUsername);
    var password = getVariableOrDefault("testPassword", defaultPassword);
    var tokenData = fetchToken(createLoginRequest(username, password), "Login", false);

    if (tokenData === null && (username !== defaultUsername || password !== defaultPassword)) {
        tokenData = fetchToken(createLoginRequest(defaultUsername, defaultPassword), "LoginDefaultFallback", false);
    }

    if (tokenData === null) {
        throw "REST Login failed. Check loginBaseUrl, testUsername, and testPassword. Expected /api/login.";
    }

    bearerToken = tokenData.accessToken;
    refreshToken = normalizeRefreshTokenValue(tokenData.refreshToken);
    tokenExpiresAt = tokenData.expiresAt;

    validateTokenIfEnabled();
}

function reauthenticateWithRefreshToken() {
    refreshToken = normalizeRefreshTokenValue(refreshToken);
    var refreshRequest = createRefreshTokenRequest(refreshToken);
    var tokenData = fetchToken(refreshRequest, "RefreshToken", false);
    if (tokenData === null) {
        bearerToken = null;
        refreshToken = null;
        tokenExpiresAt = null;
        authenticateWithLogin();
        return;
    }

    bearerToken = tokenData.accessToken;
    refreshToken = normalizeRefreshTokenValue(tokenData.refreshToken) || refreshToken;
    tokenExpiresAt = tokenData.expiresAt;

    validateTokenIfEnabled();
}

function createLoginRequest(username, password) {
    var loginUrl = getLoginUrl();

    var tokenRequest = httpClient.createRequest(loginUrl);
    tokenRequest.addHeader("Content-Type", "application/json");
    tokenRequest.addHeader("Accept", "application/json");
    tokenRequest.addHeader("user-agent", "Veracode DAST");
    tokenRequest.setMethod("POST");
    tokenRequest.setBody(buildLoginBody(username, password));

    return tokenRequest;
}

function createRefreshTokenRequest(currentRefreshToken) {
    var refreshUrl = getRefreshUrl();

    var tokenRequest = httpClient.createRequest(refreshUrl);
    tokenRequest.addHeader("Content-Type", "application/json");
    tokenRequest.addHeader("Accept", "application/json");
    if (bearerToken !== null && bearerToken !== "") {
        tokenRequest.addHeader("Authorization", "Bearer " + bearerToken);
    }
    tokenRequest.setMethod("POST");
    tokenRequest.setBody(buildRefreshTokenBody(currentRefreshToken));

    return tokenRequest;
}

function createValidateTokenRequest(currentAccessToken) {
    var validateUrl = getValidateUrl();

    var tokenRequest = httpClient.createRequest(validateUrl);
    tokenRequest.addHeader("Accept", "application/json");
    tokenRequest.addHeader("Authorization", "Bearer " + currentAccessToken);
    tokenRequest.setMethod("GET");

    return tokenRequest;
}

function fetchToken(tokenRequest, actionName, throwOnFailure) {
    var response = tokenRequest.send();
    var responseBody = response.asString();
    var tokenData = parseJson(responseBody, throwOnFailure);

    if (tokenData === null || tokenData.accessToken === null || tokenData.accessToken === "") {
        if (throwOnFailure === true) {
            throw "REST " + actionName + " failed. accessToken not found. Response: " + responseBody;
        }
        return null;
    }

    if (tokenData.expiresAt === null || tokenData.expiresAt === "") {
        if (throwOnFailure === true) {
            throw "REST " + actionName + " failed. expiresAt not found. Response: " + responseBody;
        }
        return null;
    }

    return {
        accessToken: tokenData.accessToken,
        refreshToken: tokenData.refreshToken,
        expiresAt: parseInt(tokenData.expiresAt, 10) * 1000
    };
}

function validateTokenIfEnabled() {
    var shouldValidate = vc.variables['validateTokenOnAuth'];
    if (shouldValidate !== "true") {
        return;
    }

    var validateRequest = createValidateTokenRequest(bearerToken);
    var response = validateRequest.send();
    var responseBody = response.asString();
    var validationData = parseJson(responseBody, false);

    if (validationData === null) {
        return;
    }
}

function parseJson(jsonText, throwOnFailure) {
    try {
        return JSON.parse(jsonText);
    } catch (e) {
        if (throwOnFailure === true) {
            throw "Invalid JSON response: " + jsonText;
        }
        return null;
    }
}

function getVariableOrDefault(name, fallback) {
    var value = vc.variables[name];
    if (value === null || value === undefined || trimValue(String(value)) === "") {
        return fallback;
    }
    return trimValue(String(value));
}

function trimValue(value) {
    return value.replace(/^\s+|\s+$/g, "");
}

function isTokenExpired() {
    if (tokenExpiresAt === null) {
        return true;
    }

    var currentTime = new Date().getTime();
    var bufferTime = 30 * 1000;

    return currentTime >= (tokenExpiresAt - bufferTime);
}

function updateRequestHeaders(token) {
    request.addHeader("Authorization", "Bearer " + token);
}

function updateCurrentRefreshRequestBodyIfNeeded() {
    var currentPath = getCurrentRequestPath();
    if (!currentPath.match(/\/api\/refresh\/?$/i)) {
        return;
    }

    request.addHeader("Content-Type", "application/json");
    request.addHeader("Accept", "application/json");
    if (bearerToken !== null && bearerToken !== "") {
        request.addHeader("Authorization", "Bearer " + bearerToken);
    }
    if (typeof request.setMethod === "function") {
        request.setMethod("POST");
    }
    if (typeof request.setBody === "function") {
        request.setBody(buildRefreshTokenBody(normalizeRefreshTokenValue(refreshToken)));
    }
}

function buildLoginBody(username, password) {
    return "{\"username\":\"" + escapeJson(username) + "\",\"password\":\"" + escapeJson(password) + "\"}";
}

function buildRefreshTokenBody(currentRefreshToken) {
    return "{\"refreshToken\":\"" + escapeJson(normalizeRefreshTokenValue(currentRefreshToken)) + "\"}";
}

function normalizeRefreshTokenValue(value) {
    if (value === null || value === undefined) {
        return "";
    }
    var normalized = trimValue(String(value));
    var upper = normalized.toUpperCase();
    if (
        normalized === "" ||
        upper === "[REDACTED]" ||
        upper === "REDACTED" ||
        upper === "NULL" ||
        upper === "UNDEFINED" ||
        upper === "YOUR_REFRESH_TOKEN"
    ) {
        return "";
    }
    return normalized;
}

function getCurrentRequestPath() {
    var currentUrl = getCurrentRequestUrl();
    var withoutHash = currentUrl.split("#")[0];
    var withoutQuery = withoutHash.split("?")[0];
    var schemeIndex = withoutQuery.indexOf("://");
    if (schemeIndex >= 0) {
        var pathIndex = withoutQuery.indexOf("/", schemeIndex + 3);
        if (pathIndex >= 0) {
            return withoutQuery.substring(pathIndex);
        }
        return "/";
    }
    return withoutQuery;
}

function getCurrentRequestUrl() {
    try {
        if (typeof request.getUrl === "function") {
            return String(request.getUrl());
        }
        if (typeof request.getURI === "function") {
            return String(request.getURI());
        }
        if (typeof request.getUri === "function") {
            return String(request.getUri());
        }
        if (request.url !== undefined) {
            return String(request.url);
        }
    } catch (ignored) {
        return "";
    }
    return "";
}

function getLoginUrl() {
    var configuredUrl = vc.variables['loginBaseUrl'];
    if (configuredUrl !== null && configuredUrl !== "") {
        return normalizeRestUrl(configuredUrl, "/api/login");
    }

    return "https://ca-rest-soap-labs.wonderfulcoast-2578bc9b.eastus.azurecontainerapps.io/api/login";
}

function getRefreshUrl() {
    var configuredUrl = vc.variables['refreshBaseUrl'];
    if (configuredUrl !== null && configuredUrl !== "") {
        return normalizeRestUrl(configuredUrl, "/api/refresh");
    }

    return replaceLastPath(getLoginUrl(), "/api/refresh");
}

function getValidateUrl() {
    var configuredUrl = vc.variables['validateBaseUrl'];
    if (configuredUrl !== null && configuredUrl !== "") {
        return normalizeRestUrl(configuredUrl, "/api/validate");
    }

    return replaceLastPath(getLoginUrl(), "/api/validate");
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

function escapeJson(value) {
    return String(value)
        .replace(/\\/g, "\\\\")
        .replace(/"/g, "\\\"")
        .replace(/\r/g, "\\r")
        .replace(/\n/g, "\\n");
}
