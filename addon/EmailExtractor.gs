/**
 * Extracts a structured email payload from a Gmail message, matching
 * the backend's AnalyzeRequest schema exactly.
 *
 * @param {string} messageId - Gmail message ID from the event object.
 * @returns {Object} Payload ready to POST to /analyze.
 */
function extractEmailData(messageId) {
  var gmailMessage = GmailApp.getMessageById(messageId);
  var fullMessageData = Gmail.Users.Messages.get("me", messageId, { format: "full" });

  var headers = _extractHeaders(fullMessageData.payload.headers);
  var attachments = _extractAttachments(gmailMessage);

  return {
    message_id: messageId,
    sender: gmailMessage.getFrom(),
    recipient: gmailMessage.getTo(),
    subject: gmailMessage.getSubject(),
    body_text: gmailMessage.getPlainBody() || "",
    body_html: gmailMessage.getBody() || "",
    headers: headers,
    attachments: attachments,
    date: gmailMessage.getDate().toISOString(),
  };
}

/**
 * Converts Gmail API headers to the backend's HeaderEntry[] format.
 * Preserves all headers including repeated ones (Received, Authentication-Results).
 *
 * @param {Object[]} gmailHeaders - Array of {name, value} from Gmail API.
 * @returns {Object[]} Array of {name, value} matching HeaderEntry schema.
 */
function _extractHeaders(gmailHeaders) {
  if (!gmailHeaders) return [];

  return gmailHeaders.map(function (header) {
    return {
      name: header.name,
      value: header.value,
    };
  });
}

/**
 * Extracts attachment metadata without downloading binary content.
 * Computes SHA-256 hash of each attachment's bytes.
 *
 * @param {GmailMessage} message - Gmail message object.
 * @returns {Object[]} Array matching AttachmentRequest schema.
 */
function _extractAttachments(gmailMessage) {
  var attachments = gmailMessage.getAttachments();
  if (!attachments || attachments.length === 0) return [];

  return attachments.map(function (attachment) {
    var attachmentBytes = attachment.getBytes();
    var attachmentHash = _sha256Hex(attachmentBytes);

    return {
      filename: attachment.getName(),
      mime_type: attachment.getContentType(),
      size_bytes: attachmentBytes.length,
      sha256: attachmentHash,
    };
  });
}

/**
 * Computes lowercase hex SHA-256 digest of a byte array.
 *
 * @param {Byte[]} bytes - Raw bytes to hash.
 * @returns {string} 64-character lowercase hex digest.
 */
function _sha256Hex(bytes) {
  var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);

  return digest
    .map(function (byte) {
      var hex = (byte < 0 ? byte + 256 : byte).toString(16);
      return hex.length === 1 ? "0" + hex : hex;
    })
    .join("");
}
