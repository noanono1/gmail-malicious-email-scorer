/**
 * Activates temporary Gmail access for the currently opened message.
 */
function activateCurrentMessageAccess(event) {
  if (!event || !event.gmail || !event.gmail.accessToken) {
    throw new Error("Missing Gmail access token in add-on event.");
  }

  GmailApp.setCurrentMessageAccessToken(event.gmail.accessToken);
  console.log("Gmail access token set successfully.");
}

/**
 * Contextual trigger — called by Gmail when the user opens an email.
 *
 * Design decision: auto-analyze on open rather than requiring a manual button.
 * Security tooling should be proactive — the user shouldn't have to remember
 * to scan each email. Every opened message triggers a backend POST, which is
 * acceptable here because the analysis is stateless and lightweight (no DB,
 * no side effects). In production, we'd add per-message caching (don't
 * re-analyze the same message_id) and backend rate limiting to prevent abuse.
 */
function onGmailMessageOpen(event) {
  var messageId = "(unknown)";

  try {
    activateCurrentMessageAccess(event);
    messageId = event.gmail.messageId;
    console.log("Opened message: " + messageId);

    var cache = CacheService.getUserCache();
    var cacheKey = "analysis_" + messageId;
    var cached = cache.get(cacheKey);

    if (cached) {
      console.log("Returning cached result for: " + messageId);
      var cachedResult = JSON.parse(cached);
      return [buildAnalysisCard(cachedResult, messageId)];
    }

    var emailPayload = extractEmailData(messageId);
    logPayloadShape(emailPayload);

    var analysisResult = analyzeEmail(emailPayload);
    console.log("Analysis complete — verdict: " + analysisResult.verdict + ", score: " + analysisResult.score);

    cache.put(cacheKey, JSON.stringify(analysisResult), 120);

    return [buildAnalysisCard(analysisResult, messageId)];
  } catch (error) {
    console.log("ERROR in onGmailMessageOpen [" + messageId + "]: " + error.message);
    return [buildErrorCard(messageId)];
  }
}

/**
 * Re-analyze action — triggered by the "Re-analyze" button.
 */
function onReanalyze(event) {
  var messageId = "(unknown)";

  try {
    messageId = event.parameters.messageId;
    console.log("Re-analyze requested for: " + messageId);
    activateCurrentMessageAccess(event);

    var emailPayload = extractEmailData(messageId);
    var analysisResult = analyzeEmail(emailPayload);
    console.log("Re-analysis complete — verdict: " + analysisResult.verdict);

    var cache = CacheService.getUserCache();
    cache.put("analysis_" + messageId, JSON.stringify(analysisResult), 120);

    var card = buildAnalysisCard(analysisResult, messageId);
    return buildNavigationResponse(card);
  } catch (error) {
    console.log("ERROR in onReanalyze [" + messageId + "]: " + error.message);
    var errorCard = buildErrorCard(messageId);
    return buildNavigationResponse(errorCard);
  }
}

/**
 * Logs only the *shape* of the extracted payload — sizes and counts, never
 * content. Subject, body, headers, and addresses are attacker-controlled
 * and must not appear in Stackdriver.
 */
function logPayloadShape(emailPayload) {
  console.log("Email extracted: " + JSON.stringify({
    message_id: emailPayload.message_id,
    body_text_chars: (emailPayload.body_text || "").length,
    body_html_chars: (emailPayload.body_html || "").length,
    header_count: (emailPayload.headers || []).length,
    attachment_count: (emailPayload.attachments || []).length,
    has_reply_to: Boolean(emailPayload.reply_to_address),
    has_return_path: Boolean(emailPayload.return_path_address),
  }));
}

/**
 * Wraps a card in an ActionResponse that replaces the current card.
 */
function buildNavigationResponse(card) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(card))
    .build();
}
