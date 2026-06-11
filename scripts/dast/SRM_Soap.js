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
    updateCurrentProductRequestBodyIfNeeded();
}

function authenticateWithLogin() {
    var username = getVariableOrDefault("testUsername", defaultUsername);
    var password = getVariableOrDefault("testPassword", defaultPassword);
    var tokenData = fetchToken(createLoginRequest(username, password), "Login", false);

    if (tokenData === null && (username !== defaultUsername || password !== defaultPassword)) {
        tokenData = fetchToken(createLoginRequest(defaultUsername, defaultPassword), "LoginDefaultFallback", false);
    }

    if (tokenData === null) {
        throw "SOAP Login failed. Check loginBaseUrl, testUsername, and testPassword. Expected /soap/auth with SOAPAction Login.";
    }

    bearerToken = tokenData.accessToken;
    refreshToken = tokenData.refreshToken;
    tokenExpiresAt = tokenData.expiresAt;

    validateTokenIfEnabled();
}

function reauthenticateWithRefreshToken() {
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
    refreshToken = tokenData.refreshToken || refreshToken;
    tokenExpiresAt = tokenData.expiresAt;

    validateTokenIfEnabled();
}

function createLoginRequest(username, password) {
    var loginUrl = getAuthUrl();

    var tokenRequest = httpClient.createRequest(loginUrl);
    tokenRequest.addHeader("Content-Type", "application/xml");
    tokenRequest.addHeader("user-agent", "Veracode DAST");
    tokenRequest.addHeader("SOAPAction", "Login");
    tokenRequest.setMethod("POST");

    tokenRequest.setBody("<?xml version=\"1.0\"?>\r\n" +
        "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:lab=\"urn:soap-dast-lab\">\r\n" +
        "  <soap:Body>\r\n" +
        "    <lab:Login>\r\n" +
        "      <lab:Username>" + username + "</lab:Username>\r\n" +
        "      <lab:Password>" + password + "</lab:Password>\r\n" +
        "    </lab:Login>\r\n" +
        "  </soap:Body>\r\n" +
        "</soap:Envelope>");

    return tokenRequest;
}

function createRefreshTokenRequest(currentRefreshToken) {
    var refreshUrl = getRefreshUrl();

    var tokenRequest = httpClient.createRequest(refreshUrl);
    tokenRequest.addHeader("Content-Type", "application/xml");
    tokenRequest.addHeader("SOAPAction", "RefreshToken");
    if (currentRefreshToken === null || currentRefreshToken === "") {
        tokenRequest.addHeader("Authorization", "Bearer " + bearerToken);
    }
    tokenRequest.setMethod("POST");

    tokenRequest.setBody(buildRefreshTokenEnvelope(currentRefreshToken));

    return tokenRequest;
}

function createValidateTokenRequest(currentAccessToken) {
    var validateUrl = getAuthUrl();

    var tokenRequest = httpClient.createRequest(validateUrl);
    tokenRequest.addHeader("Content-Type", "application/xml");
    tokenRequest.addHeader("SOAPAction", "ValidateToken");
    tokenRequest.addHeader("Authorization", "Bearer " + currentAccessToken);
    tokenRequest.setMethod("POST");

    tokenRequest.setBody("<?xml version=\"1.0\"?>\r\n" +
        "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:lab=\"urn:soap-dast-lab\">\r\n" +
        "  <soap:Body>\r\n" +
        "    <lab:ValidateToken/>\r\n" +
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

    if (accessToken === null || accessToken === "") {
        if (throwOnFailure === true) {
            throw "SOAP " + actionName + " failed. AccessToken not found. Response: " + responseBody;
        }
        return null;
    }

    if (expiresAt === null || expiresAt === "") {
        if (throwOnFailure === true) {
            throw "SOAP " + actionName + " failed. ExpiresAt not found. Response: " + responseBody;
        }
        return null;
    }

    return {
        accessToken: accessToken,
        refreshToken: newRefreshToken,
        expiresAt: parseInt(expiresAt, 10) * 1000
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
    var subject = getXmlTagValue(responseBody, "Subject");

    if (subject === null || subject === "") {
        return;
    }
}

function getVariableOrDefault(name, fallback) {
    var value = vc.variables[name];
    if (value === null || value === undefined || trimValue(String(value)) === "") {
        return fallback;
    }
    return trimValue(String(value));
}

function getXmlTagValue(xml, tagName) {
    var leafRegex = new RegExp("<(?:[A-Za-z0-9_]+:)?" + tagName + "(?:\\s[^>]*)?>([^<>]*)</(?:[A-Za-z0-9_]+:)?" + tagName + ">", "ig");
    var leafMatch = null;
    var leafValue = null;
    while ((leafMatch = leafRegex.exec(xml)) !== null) {
        if (leafMatch.length >= 2 && trimValue(leafMatch[1]) !== "") {
            leafValue = trimValue(leafMatch[1]);
        }
    }
    if (leafValue !== null) {
        return leafValue;
    }

    var regex = new RegExp("<(?:[A-Za-z0-9_]+:)?" + tagName + "(?:\\s[^>]*)?>([\\s\\S]*?)</(?:[A-Za-z0-9_]+:)?" + tagName + ">", "i");
    var match = regex.exec(xml);

    if (match === null || match.length < 2) {
        return null;
    }

    return trimValue(match[1]);
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
    if (!currentPath.match(/\/soap\/refreshtoken\/?$/i)) {
        return;
    }

    request.addHeader("Content-Type", "application/xml");
    request.addHeader("SOAPAction", "RefreshToken");
    if (bearerToken !== null && bearerToken !== "") {
        request.addHeader("Authorization", "Bearer " + bearerToken);
    }
    if (typeof request.setMethod === "function") {
        request.setMethod("POST");
    }
    if (typeof request.setBody === "function") {
        request.setBody(buildRefreshTokenEnvelope(refreshToken));
    }
}

function updateCurrentProductRequestBodyIfNeeded() {
    var currentPath = getCurrentRequestPath();
    if (!currentPath.match(/\/admin\/products\/?$/i)) {
        return;
    }

    var currentMethod = getCurrentRequestMethod();
    if (currentMethod !== "POST" && currentMethod !== "PUSH" && currentMethod !== "DELETE") {
        return;
    }

    request.addHeader("Content-Type", "application/xml");

    if (typeof request.setBody !== "function") {
        return;
    }

    if (currentMethod === "DELETE") {
        request.setBody("<product><sku>SKU-10</sku></product>");
        return;
    }

    if (currentMethod === "PUSH") {
        request.setBody("<product><sku>SKU-10</sku><name>blabla updated</name><price>209.90</price><stock>9</stock></product>");
        return;
    }

    request.setBody("<product><sku>SKU-10</sku><name>blabla</name><price>199.90</price><stock>10</stock></product>");
}

function buildRefreshTokenEnvelope(currentRefreshToken) {
    var tokenElement = "";
    if (currentRefreshToken !== null && currentRefreshToken !== "") {
        tokenElement = "      <lab:RefreshToken>" + escapeXml(currentRefreshToken) + "</lab:RefreshToken>\r\n";
    }
    return "<?xml version=\"1.0\"?>\r\n" +
        "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:lab=\"urn:soap-dast-lab\">\r\n" +
        "  <soap:Body>\r\n" +
        "    <lab:RefreshToken>\r\n" +
        tokenElement +
        "    </lab:RefreshToken>\r\n" +
        "  </soap:Body>\r\n" +
        "</soap:Envelope>";
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

function getCurrentRequestMethod() {
    try {
        if (typeof request.getMethod === "function") {
            return String(request.getMethod()).toUpperCase();
        }
        if (request.method !== undefined) {
            return String(request.method).toUpperCase();
        }
    } catch (ignored) {
        return "";
    }
    return "";
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

function escapeXml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&apos;");
}

function getAuthUrl() {
    var configuredUrl = vc.variables['loginBaseUrl'];
    if (configuredUrl !== null && configuredUrl !== "") {
        return normalizeAuthUrl(configuredUrl);
    }

    return "https://ca-rest-soap-labs.wonderfulcoast-2578bc9b.eastus.azurecontainerapps.io/soap/auth";
}

function getRefreshUrl() {
    var configuredUrl = vc.variables['refreshBaseUrl'];
    if (configuredUrl !== null && configuredUrl !== "") {
        return normalizeRefreshUrl(configuredUrl);
    }

    return normalizeRefreshUrl(getAuthUrl());
}

function normalizeAuthUrl(url) {
    var normalized = trimValue(url);

    if (normalized.match(/\/soap\/auth\/?$/i)) {
        return normalized.replace(/\/$/, "");
    }

    if (normalized.match(/\/soap\/refreshtoken\/?$/i)) {
        return normalized.replace(/\/soap\/refreshtoken\/?$/i, "/soap/auth");
    }

    if (normalized.match(/\/soap\/?$/i)) {
        return normalized.replace(/\/soap\/?$/i, "/soap/auth");
    }

    return normalized.replace(/\/$/, "") + "/soap/auth";
}

function normalizeRefreshUrl(url) {
    var normalized = trimValue(url);

    if (normalized.match(/\/soap\/refreshtoken\/?$/i)) {
        return normalized.replace(/\/$/, "");
    }

    if (normalized.match(/\/soap\/auth\/?$/i)) {
        return normalized.replace(/\/soap\/auth\/?$/i, "/soap/refreshtoken");
    }

    if (normalized.match(/\/soap\/?$/i)) {
        return normalized.replace(/\/soap\/?$/i, "/soap/refreshtoken");
    }

    return normalized.replace(/\/$/, "") + "/soap/refreshtoken";
}
