/**
 * Verdict display configuration — colors and icons per verdict tier.
 */
var VERDICT_STYLES = {
  safe:             { color: "#1B8332", icon: "✓", label: "SAFE" },
  suspicious:       { color: "#F9A825", icon: "⚠", label: "SUSPICIOUS" },
  likely_malicious: { color: "#E65100", icon: "⚠", label: "LIKELY MALICIOUS" },
  malicious:        { color: "#C62828", icon: "✕", label: "MALICIOUS" },
};

/**
 * Builds the main analysis result card from the backend response.
 *
 * @param {Object} result - Parsed AnalyzeResponse from the backend.
 * @returns {CardService.Card} Fully rendered analysis card.
 */
function buildAnalysisCard(result) {
  var verdictStyle = VERDICT_STYLES[result.verdict] || VERDICT_STYLES.safe;
  var cardBuilder = CardService.newCardBuilder();

  // --- Header section: verdict + score ---
  var headerSection = CardService.newCardSection();
  headerSection.addWidget(
    CardService.newTextParagraph().setText(
      "<b><font color=\"" + verdictStyle.color + "\">" +
      verdictStyle.icon + " " + verdictStyle.label +
      "</font></b>          Score: " +
      Math.round(result.score) + "/100"
    )
  );
  cardBuilder.addSection(headerSection);

  // --- Summary section ---
  if (result.explanation) {
    var summarySection = CardService.newCardSection().setHeader("Summary");
    summarySection.addWidget(
      CardService.newTextParagraph().setText(result.explanation)
    );
    cardBuilder.addSection(summarySection);
  }

  // --- Top findings section ---
  if (result.top_signals && result.top_signals.length > 0) {
    var findingsSection = CardService.newCardSection().setHeader("Top Findings");

    result.top_signals.forEach(function (signal) {
      var severityLabel = signal.severity.toUpperCase();
      var categoryLabel = signal.category.replace(/_/g, " ").toUpperCase();
      var contribution = "+" + signal.score_contribution.toFixed(1) + " pts";

      findingsSection.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(categoryLabel + "  ·  " + severityLabel)
          .setText(signal.evidence)
          .setBottomLabel(contribution)
      );
    });

    cardBuilder.addSection(findingsSection);
  }

  // --- Blind spots section ---
  if (result.blind_spots && result.blind_spots.length > 0) {
    var blindSpotsSection = CardService.newCardSection()
      .setHeader("Blind Spots (" + result.blind_spots.length + ")")
      .setCollapsible(true)
      .setNumUncollapsibleWidgets(0);

    result.blind_spots.forEach(function (blindSpot) {
      blindSpotsSection.addWidget(
        CardService.newDecoratedText()
          .setText(blindSpot.risk_note)
          .setBottomLabel(blindSpot.reason)
      );
    });

    cardBuilder.addSection(blindSpotsSection);
  }

  // --- Analysis scope section ---
  if (result.scope) {
    var scopeSection = CardService.newCardSection()
      .setHeader("Analysis Scope")
      .setCollapsible(true)
      .setNumUncollapsibleWidgets(0);

    var scopeSummaryLines = [];
    if (result.scope.analyzers_run.length > 0) {
      scopeSummaryLines.push("Analyzers: " + result.scope.analyzers_run.join(", "));
    } else {
      scopeSummaryLines.push("Analyzers: none (skeleton mode)");
    }
    if (result.scope.intel_sources_run.length > 0) {
      scopeSummaryLines.push("Intel: " + result.scope.intel_sources_run.join(", "));
    }
    scopeSummaryLines.push(
      "HTML: " + (result.scope.has_html ? "yes" : "no") +
      "  |  Attachments: " + (result.scope.has_attachments ? "yes" : "no") +
      "  |  Auth headers: " + (result.scope.has_auth_headers ? "yes" : "no")
    );

    scopeSection.addWidget(
      CardService.newTextParagraph().setText(scopeSummaryLines.join("\n"))
    );
    cardBuilder.addSection(scopeSection);
  }

  // --- Re-analyze button ---
  var actionSection = CardService.newCardSection();
  var reanalyzeAction = CardService.newAction()
    .setFunctionName("onReanalyze")
    .setParameters({ messageId: result.message_id || "" });

  actionSection.addWidget(
    CardService.newTextButton()
      .setText("↻ Re-analyze")
      .setOnClickAction(reanalyzeAction)
  );
  cardBuilder.addSection(actionSection);

  return cardBuilder.build();
}

/**
 * Builds the error card shown when the backend is unreachable or returns an error.
 * Never implies safety on failure.
 *
 * @param {string} errorMessage - Error description for logging context.
 * @returns {CardService.Card} Error card with retry button.
 */
function buildErrorCard(errorMessage) {
  var cardBuilder = CardService.newCardBuilder();

  var section = CardService.newCardSection();
  section.addWidget(
    CardService.newTextParagraph().setText(
      "<b>Analysis Unavailable</b>"
    )
  );
  section.addWidget(
    CardService.newTextParagraph().setText(
      "Could not reach the analysis backend. " +
      "This does not mean the email is safe."
    )
  );

  var retryAction = CardService.newAction()
    .setFunctionName("onGmailMessageOpen");

  section.addWidget(
    CardService.newTextButton()
      .setText("↻ Retry")
      .setOnClickAction(retryAction)
  );

  cardBuilder.addSection(section);
  return cardBuilder.build();
}
