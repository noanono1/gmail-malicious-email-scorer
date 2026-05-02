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

    var emailPayload = extractEmailData(messageId);
    var analysisResult = analyzeEmail(emailPayload);
    console.log("Analysis complete — verdict: " + analysisResult.verdict + ", score: " + analysisResult.score);

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
  var messageId = event.parameters.messageId;
  console.log("Re-analyze requested for: " + messageId);

  try {
    activateCurrentMessageAccess(event);

    var emailPayload = extractEmailData(messageId);
    var analysisResult = analyzeEmail(emailPayload);
    console.log("Re-analysis complete — verdict: " + analysisResult.verdict);

    var card = buildAnalysisCard(analysisResult, messageId);
    return buildNavigationResponse(card);
  } catch (error) {
    console.log("ERROR in onReanalyze [" + messageId + "]: " + error.message);
    var errorCard = buildErrorCard(messageId);
    return buildNavigationResponse(errorCard);
  }
}

/**
 * Wraps a card in an ActionResponse that replaces the current card.
 */
function buildNavigationResponse(card) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(card))
    .build();
}
