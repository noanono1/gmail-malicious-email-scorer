/**
 * Sends the email payload to the backend /analyze endpoint with HMAC signing.
 *
 * Note: the byte-to-hex helper (`bytesToHex`) used by `computeHmacSignature`
 * below lives in `EmailExtractor.gs`. Apps Script merges every `.gs` file
 * in a project into a single global namespace at runtime, so the import
 * is implicit — keep the two files together when copying the add-on.
 */
function analyzeEmail(emailPayload) {
  var backendUrl = getRequiredProperty("BACKEND_URL").replace(/\/+$/, "");
  var hmacSecret = getRequiredProperty("HMAC_SECRET");
  var endpoint = backendUrl + "/analyze";

  console.log("Sending analysis request to: " + endpoint);

  var requestBody = JSON.stringify(emailPayload);
  var timestamp = Math.floor(Date.now() / 1000).toString();
  var signature = computeHmacSignature(hmacSecret, timestamp, requestBody);

  var response = sendSignedRequest(endpoint, requestBody, timestamp, signature);
  return parseAnalysisResponse(response);
}

/**
 * Sends a signed POST request to the backend.
 */
function sendSignedRequest(url, body, timestamp, signature) {
  var blob = Utilities.newBlob(body, "application/json; charset=utf-8");

  var response = UrlFetchApp.fetch(url, {
    method: "post",
    headers: {
      "X-Timestamp": timestamp,
      "X-Signature": signature,
    },
    payload: blob,
    muteHttpExceptions: true,
  });

  console.log("Backend responded with status: " + response.getResponseCode());
  return response;
}

/**
 * Parses the backend response, throwing on non-200 status codes.
 */
function parseAnalysisResponse(response) {
  var statusCode = response.getResponseCode();
  var responseText = response.getContentText();

  if (statusCode !== 200) {
    var errorDetail = tryExtractErrorDetail(responseText);
    var message = "Backend returned " + statusCode + (errorDetail ? ": " + errorDetail : "");
    console.log("Backend error: " + message);
    throw new Error(message);
  }

  var parsed = JSON.parse(responseText);
  console.log("Analysis response parsed — verdict: " + parsed.verdict);
  return parsed;
}

/**
 * Attempts to extract a detail message from a JSON error response.
 */
function tryExtractErrorDetail(responseText) {
  try {
    return JSON.parse(responseText).detail || "";
  } catch (_) {
    return "";
  }
}

/**
 * Computes HMAC-SHA256 signature: sign(timestamp.body) with the shared secret.
 * The dot separator prevents ambiguity between timestamp and body boundaries.
 */
function computeHmacSignature(secret, timestamp, body) {
  var dataToSign = timestamp + "." + body;
  var signatureBytes = Utilities.computeHmacSignature(
    Utilities.MacAlgorithm.HMAC_SHA_256,
    dataToSign,
    secret,
    Utilities.Charset.UTF_8
  );

  return bytesToHex(signatureBytes);
}

/**
 * Reads a required script property, throwing if missing.
 */
function getRequiredProperty(key) {
  var value = PropertiesService.getScriptProperties().getProperty(key);
  if (!value) {
    throw new Error("Missing script property: " + key);
  }
  return value;
}
