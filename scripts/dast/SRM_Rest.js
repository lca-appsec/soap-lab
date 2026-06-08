var bearerToken = null;
var refreshToken = null;
var tokenExpiresAt = null;

function run() {
    if (bearerToken === null) {
        authenticateWithLogin();
    } else if (isTokenExpired()) {
        reauthenticateWithRefreshToken();
    }

    updateRequestHeaders(bearerToken);
}

function authenticateWithLogin() {
    var tokenRequest = createLoginRequest();
    var tokenData = fetchToken(tokenRequest, "Login");

    bearerToken = tokenData.accessToken;
    refreshToken = tokenData.refreshToken;
    tokenExpiresAt = tokenData.expiresAt;

    validateTokenIfEnabled();
}

function reauthenticateWithRefreshToken() {
    if (refreshToken === null || refreshToken === "") {
        authenticateWithLogin();
        return;
    }

    var refreshRequest = createRefreshTokenRequest(refreshToken);
    var tokenData = fetchToken(refreshRequest, "RefreshToken");

    bearerToken = tokenData.accessToken;
    refreshToken = tokenData.refreshToken;
    tokenExpiresAt = tokenData.expiresAt;

    validateTokenIfEnabled();
}

function createLoginRequest() {
    var username = vc.variables['testUsername'];
    var password = vc.variables['testPassword'];
    var loginUrl = getLoginUrl();

    var tokenRequest = httpClient.createRequest(loginUrl);
    tokenRequest.addHeader("Content-Type", "application/json");
    tokenRequest.addHeader("Accept", "application/json");
    tokenRequest.addHeader("user-agent", "Veracode DAST");
    tokenRequest.setMethod("POST");
    tokenRequest.setBody("{\"username\":\"" + escapeJson(username) + "\",\"password\":\"" + escapeJson(password) + "\"}");

    return tokenRequest;
}

function createRefreshTokenRequest(currentRefreshToken) {
    var refreshUrl = getRefreshUrl();

    var tokenRequest = httpClient.createRequest(refreshUrl);
    tokenRequest.addHeader("Content-Type", "application/json");
    tokenRequest.addHeader("Accept", "application/json");
    tokenRequest.setMethod("POST");
    tokenRequest.setBody("{\"refreshToken\":\"" + escapeJson(currentRefreshToken) + "\"}");

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

function fetchToken(tokenRequest, actionName) {
    var response = tokenRequest.send();
    var responseBody = response.asString();
    var tokenData = parseJson(responseBody);

    if (tokenData.accessToken === null || tokenData.accessToken === "") {
        throw "REST " + actionName + " failed. accessToken not found. Response: " + responseBody;
    }

    if (tokenData.expiresAt === null || tokenData.expiresAt === "") {
        throw "REST " + actionName + " failed. expiresAt not found. Response: " + responseBody;
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
    var validationData = parseJson(responseBody);

    if (validationData.valid !== true && validationData.subject === null && validationData.sub === null) {
        throw "REST ValidateToken failed. Response: " + responseBody;
    }
}

function parseJson(jsonText) {
    try {
        return JSON.parse(jsonText);
    } catch (e) {
        throw "Invalid JSON response: " + jsonText;
    }
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
