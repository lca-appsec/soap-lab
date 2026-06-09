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
    var refreshUrl = getAuthUrl();

    var tokenRequest = httpClient.createRequest(refreshUrl);
    tokenRequest.addHeader("Content-Type", "application/xml");
    tokenRequest.addHeader("SOAPAction", "RefreshToken");
    tokenRequest.setMethod("POST");

    tokenRequest.setBody("<?xml version=\"1.0\"?>\r\n" +
        "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:lab=\"urn:soap-dast-lab\">\r\n" +
        "  <soap:Body>\r\n" +
        "    <lab:RefreshToken>\r\n" +
        "      <lab:RefreshToken>" + currentRefreshToken + "</lab:RefreshToken>\r\n" +
        "    </lab:RefreshToken>\r\n" +
        "  </soap:Body>\r\n" +
        "</soap:Envelope>");

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

function fetchToken(tokenRequest, actionName) {
    var response = tokenRequest.send();
    var responseBody = response.asString();

    var accessToken = getXmlTagValue(responseBody, "AccessToken");
    var newRefreshToken = getXmlTagValue(responseBody, "RefreshToken");
    var expiresAt = getXmlTagValue(responseBody, "ExpiresAt");

    if (accessToken === null || accessToken === "") {
        throw "SOAP " + actionName + " failed. AccessToken not found. Response: " + responseBody;
    }

    if (expiresAt === null || expiresAt === "") {
        throw "SOAP " + actionName + " failed. ExpiresAt not found. Response: " + responseBody;
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
        throw "SOAP ValidateToken failed. Response: " + responseBody;
    }
}

function getXmlTagValue(xml, tagName) {
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

function getAuthUrl() {
    var configuredUrl = vc.variables['loginBaseUrl'];
    if (configuredUrl !== null && configuredUrl !== "") {
        return normalizeAuthUrl(configuredUrl);
    }

    return "https://ca-rest-soap-labs.wonderfulcoast-2578bc9b.eastus.azurecontainerapps.io/soap/auth";
}

function normalizeAuthUrl(url) {
    var normalized = trimValue(url);

    if (normalized.match(/\/soap\/auth\/?$/i)) {
        return normalized.replace(/\/$/, "");
    }

    if (normalized.match(/\/soap\/?$/i)) {
        return normalized.replace(/\/soap\/?$/i, "/soap/auth");
    }

    return normalized.replace(/\/$/, "") + "/soap/auth";
}
