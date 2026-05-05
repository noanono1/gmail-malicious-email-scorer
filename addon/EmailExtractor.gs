/**
 * Extracts a structured email payload matching the backend's AnalyzeRequest schema.
 */
function extractEmailData(messageId) {
  console.log("Extracting email data for: " + messageId);
  var gmailMessage = GmailApp.getMessageById(messageId);

  var parsedSender = parseFromField(gmailMessage.getFrom());
  var subject = gmailMessage.getSubject();
  var attachments = extractAttachmentMetadata(gmailMessage);

  console.log("Extracted email — attachments: " + attachments.length);

  var replyToRaw = gmailMessage.getReplyTo();
  var returnPathRaw = gmailMessage.getHeader("Return-Path") || "";

  return {
    message_id: messageId,
    sender_address: parsedSender.address,
    sender_display_name: parsedSender.displayName,
    recipient: gmailMessage.getTo(),
    subject: subject,
    body_text: gmailMessage.getPlainBody() || "",
    body_html: gmailMessage.getBody() || "",
    reply_to_address: extractAddress(replyToRaw),
    return_path_address: extractAddress(returnPathRaw),
    headers: extractSecurityHeaders(gmailMessage, messageId),
    attachments: attachments,
    date: gmailMessage.getDate().toISOString(),
  };
}

/**
 * Splits a raw From field into address and display name.
 * "Display Name" <user@example.com> → { address, displayName }
 * user@example.com                  → { address, displayName: "" }
 */
function parseFromField(rawFrom) {
  var match = rawFrom.match(/<([^>]+)>/);
  if (match) {
    var address = match[1];
    var displayName = rawFrom.replace(/<[^>]+>/, "").trim().replace(/^"|"$/g, "");
    return { address: address, displayName: displayName };
  }
  return { address: rawFrom.trim(), displayName: "" };
}

/**
 * Extracts a bare email address from a header value.
 * "<user@example.com>" → "user@example.com"
 * "user@example.com"   → "user@example.com"
 */
function extractAddress(headerValue) {
  if (!headerValue) return "";
  var match = headerValue.match(/<([^>]+)>/);
  return match ? match[1] : headerValue.trim();
}

var SECURITY_HEADERS = [
  "Authentication-Results",
  "Received-SPF",
  "DKIM-Signature",
  "ARC-Authentication-Results",
  "X-Mailer",
  "X-Originating-IP",
  "Received",
  "To",
  "Message-ID",
  "Content-Type",
];

/**
 * Extracts security-relevant headers, preserving duplicates.
 *
 * Primary path: Gmail Advanced Service with format:"metadata" — returns
 * payload.headers as an ordered array including every occurrence (the
 * backend AuthenticationAnalyzer relies on seeing all Authentication-Results
 * values to apply its "first MTA wins" rule).
 *
 * Fallback: GmailMessage.getHeader() per name. Only one value per repeated
 * header, but the add-on still produces a usable payload if the API call
 * fails (advanced service disabled, transient error, etc.).
 */
function extractSecurityHeaders(gmailMessage, messageId) {
  try {
    return fetchSecurityHeadersViaGmailApi(messageId);
  } catch (error) {
    console.warn(
      "Gmail metadata API failed for " + messageId + " (" + error.message +
      ") — falling back to GmailMessage.getHeader(). Repeated headers " +
      "(Authentication-Results, Received, Received-SPF) may be truncated."
    );
    return extractSecurityHeadersFallback(gmailMessage);
  }
}

/**
 * Calls Gmail.Users.Messages.get with format:"metadata" to fetch only the
 * named security headers — no body, no attachments downloaded. Preserves
 * order and duplicates.
 */
function fetchSecurityHeadersViaGmailApi(messageId) {
  var response = Gmail.Users.Messages.get("me", messageId, {
    format: "metadata",
    metadataHeaders: SECURITY_HEADERS,
  });

  var rawHeaders = (response && response.payload && response.payload.headers) || [];
  var headers = rawHeaders.map(function (h) {
    return { name: h.name, value: h.value };
  });

  logExtractedSecurityHeaders(headers, "gmail_api");
  return headers;
}

/**
 * Per-name extraction via GmailMessage.getHeader(). Only one value returned
 * per header name — used as graceful degradation when the Advanced Service
 * is unavailable.
 */
function extractSecurityHeadersFallback(gmailMessage) {
  var headers = [];
  SECURITY_HEADERS.forEach(function (headerName) {
    var value = gmailMessage.getHeader(headerName);
    if (value) {
      headers.push({ name: headerName, value: value });
    }
  });
  logExtractedSecurityHeaders(headers, "fallback");
  return headers;
}

/**
 * Logs which headers were extracted and how many times each appeared,
 * without dumping values. Authentication-Results and Received chains can
 * leak internal routing/IP info — names + counts only.
 */
function logExtractedSecurityHeaders(headers, source) {
  var counts = {};
  headers.forEach(function (h) {
    counts[h.name] = (counts[h.name] || 0) + 1;
  });
  var summary = Object.keys(counts).map(function (name) {
    return name + "=" + counts[name];
  }).join(", ");
  console.log(
    "Security headers via " + source + " — total " + headers.length +
    (summary ? " (" + summary + ")" : "")
  );
}

/**
 * Extracts attachment metadata without downloading binary content.
 */
function extractAttachmentMetadata(gmailMessage) {
  var attachments = gmailMessage.getAttachments();
  if (!attachments || attachments.length === 0) return [];

  return attachments.map(function (attachment) {
    var name = attachment.getName();
    var sizeBytes = attachment.getSize();

    return {
      filename: name,
      mime_type: attachment.getContentType(),
      size_bytes: sizeBytes,
      sha256: computeAttachmentSha256(attachment),
    };
  });
}

/**
 * Computes SHA-256 hash of an attachment's content.
 */
function computeAttachmentSha256(attachment) {
  try {
    var bytes = attachment.getBytes();
    var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);
    return bytesToHex(digest);
  } catch (error) {
    console.log("SHA-256 computation failed: " + error.message);
    return null;
  }
}

/**
 * Converts a byte array to a lowercase hex string.
 */
function bytesToHex(bytes) {
  return bytes
    .map(function (byte) {
      var hex = (byte < 0 ? byte + 256 : byte).toString(16);
      return hex.length === 1 ? "0" + hex : hex;
    })
    .join("");
}
