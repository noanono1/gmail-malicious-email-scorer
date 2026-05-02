/**
 * Sends the email payload to the backend's /analyze endpoint with HMAC signing.
 * Returns the parsed analysis result or throws on failure.
 *
 * @param {Object} emailPayload - Structured email data from extractEmailData().
 * @returns {Object} Parsed AnalyzeResponse from the backend.
 */
function analyzeEmail(emailPayload) {
  var backendUrl = _getProperty("BACKEND_URL");
  var hmacSecret = _getProperty("HMAC_SECRET");

  var requestBody = JSON.stringify(emailPayload);
  var timestamp = Math.floor(Date.now() / 1000).toString();
  var signature = _computeHmac(hmacSecret, timestamp, requestBody);

  var response = UrlFetchApp.fetch(backendUrl + "/analyze", {
    method: "post",
    contentType: "application/json",
    headers: {
      "X-Timestamp": timestamp,
      "X-Signature": signature,
    },
    payload: requestBody,
    muteHttpExceptions: true,
  });

  var statusCode = response.getResponseCode();
  if (statusCode !== 200) {
    var errorDetail = "";
    try {
      errorDetail = JSON.parse(response.getContentText()).detail || "";
    } catch (_) {}
    throw new Error(
      "Backend returned " + statusCode + (errorDetail ? ": " + errorDetail : "")
    );
  }

  return JSON.parse(response.getContentText());
}

/**
 * Computes HMAC-SHA256 signature matching the backend's verification.
 * Signs (timestamp + body) with the shared secret.
 *
 * @param {string} secret - HMAC shared secret.
 * @param {string} timestamp - Unix epoch string.
 * @param {string} body - JSON request body.
 * @returns {string} Lowercase hex HMAC digest.
 */
function _computeHmac(secret, timestamp, body) {
  var signatureBytes = Utilities.computeHmacSha256Signature(
    timestamp + body,
    secret
  );

  return signatureBytes
    .map(function (byte) {
      var hex = (byte < 0 ? byte + 256 : byte).toString(16);
      return hex.length === 1 ? "0" + hex : hex;
    })
    .join("");
}

/**
 * Reads a script property or throws a clear error if missing.
 *
 * @param {string} key - Property name.
 * @returns {string} Property value.
 */
function _getProperty(key) {
  var value = PropertiesService.getScriptProperties().getProperty(key);
  if (!value) {
    throw new Error("Missing script property: " + key);
  }
  return value;
}
