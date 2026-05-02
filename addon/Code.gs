/**
 * Contextual trigger — called by Gmail when the user opens an email.
 * Extracts the email payload, sends it to the backend, and renders
 * the analysis result as a Card UI.
 *
 * @param {Object} event - Gmail add-on event object.
 * @returns {CardService.Card[]} Cards to display in the add-on panel.
 */
function onGmailMessageOpen(event) {
  var messageId = event.gmail.messageId;

  try {
    var emailPayload = extractEmailData(messageId);
    var analysisResult = analyzeEmail(emailPayload);
    return [buildAnalysisCard(analysisResult)];
  } catch (error) {
    Logger.log("Error analyzing email: " + error.message);
    return [buildErrorCard(error.message)];
  }
}

/**
 * Re-analyze action — triggered by the "Re-analyze" button on the card.
 * Repeats the full extraction → analysis → render pipeline.
 *
 * @param {Object} event - Action event containing messageId in parameters.
 * @returns {CardService.ActionResponse} Updated card.
 */
function onReanalyze(event) {
  var messageId = event.parameters.messageId;

  try {
    var emailPayload = extractEmailData(messageId);
    var analysisResult = analyzeEmail(emailPayload);
    var card = buildAnalysisCard(analysisResult);

    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().updateCard(card))
      .build();
  } catch (error) {
    Logger.log("Re-analyze error: " + error.message);
    var errorCard = buildErrorCard(error.message);

    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().updateCard(errorCard))
      .build();
  }
}
