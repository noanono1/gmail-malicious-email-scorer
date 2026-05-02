/**
 * Extracts a structured email payload matching the backend's AnalyzeRequest schema.
 */
function extractEmailData(messageId) {
  console.log("Extracting email data for: " + messageId);
  var gmailMessage = GmailApp.getMessageById(messageId);

  var sender = gmailMessage.getFrom();
  var subject = gmailMessage.getSubject();
  var attachments = extractAttachmentMetadata(gmailMessage);

  console.log("Extracted email — attachments: " + attachments.length);

  return {
    message_id: messageId,
    sender: sender,
    recipient: gmailMessage.getTo(),
    subject: subject,
    body_text: gmailMessage.getPlainBody() || "",
    body_html: gmailMessage.getBody() || "",
    headers: extractSecurityHeaders(gmailMessage),
    attachments: attachments,
    date: gmailMessage.getDate().toISOString(),
  };
}

var SECURITY_HEADERS = [
  "Authentication-Results",
  "Received-SPF",
  "DKIM-Signature",
  "ARC-Authentication-Results",
  "Return-Path",
  "Reply-To",
  "X-Mailer",
  "X-Originating-IP",
  "Received",
  "From",
  "To",
  "Message-ID",
  "Content-Type",
];

/**
 * Extracts security-relevant headers using GmailMessage.getHeader().
 * Limitation: getHeader() returns one value per name, so repeated headers
 * (like Received, Authentication-Results) will only have their first value.
 *
 * TODO: switch to Gmail Advanced Service (Gmail.Users.Messages.get with
 * format:"metadata") to capture all repeated headers — the header analyzer
 * needs multiple Authentication-Results to see full SPF/DKIM/DMARC picture.
 */
function extractSecurityHeaders(gmailMessage) {
  var headers = [];

  SECURITY_HEADERS.forEach(function (headerName) {
    var value = gmailMessage.getHeader(headerName);
    if (value) {
      headers.push({ name: headerName, value: value });
    }
  });

  console.log("Extracted " + headers.length + " security headers.");
  return headers;
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
