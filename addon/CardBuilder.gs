// INCONCLUSIVE is intentionally non-alarming: it means "we did not have
// enough coverage to judge", not "we judged this and it looked bad". The
// neutral gray + info glyph keeps the badge from reading like a finding.
// Score is hidden in this state because there was nothing to score; see
// buildVerdictSection.
var VERDICT_STYLES = {
  safe:             { color: "#1B8332", icon: "✓", label: "SAFE",             hideScore: false },
  inconclusive:     { color: "#5F6368", icon: "ⓘ", label: "INCONCLUSIVE",     hideScore: true  },
  suspicious:       { color: "#F9A825", icon: "⚠", label: "SUSPICIOUS",       hideScore: false },
  likely_malicious: { color: "#E65100", icon: "⚠", label: "LIKELY MALICIOUS", hideScore: false },
  malicious:        { color: "#C62828", icon: "✕", label: "MALICIOUS",        hideScore: false },
  _unknown:         { color: "#757575", icon: "?", label: "UNKNOWN",          hideScore: true  },
};

/**
 * Builds the main analysis result card from the backend response.
 */
function buildAnalysisCard(result, messageId) {
  var verdictStyle = VERDICT_STYLES[result.verdict] || VERDICT_STYLES._unknown;
  var cardBuilder = CardService.newCardBuilder();

  cardBuilder.addSection(buildVerdictSection(result, verdictStyle));

  if (result.explanation) {
    cardBuilder.addSection(buildSummarySection(result.explanation));
  }

  if (result.top_signals && result.top_signals.length > 0) {
    cardBuilder.addSection(buildFindingsSection(result.top_signals));
  }

  if (result.blind_spots && result.blind_spots.length > 0) {
    cardBuilder.addSection(buildBlindSpotsSection(result.blind_spots));
  }

  if (result.scope) {
    cardBuilder.addSection(buildScopeSection(result.scope));
  }

  cardBuilder.addSection(buildReanalyzeSection(messageId));

  return cardBuilder.build();
}

/**
 * Verdict badge, with score appended unless the verdict style suppresses
 * it. Score is hidden for INCONCLUSIVE (and for unrecognised verdicts)
 * because a numeric score next to "we couldn't judge" is contradictory —
 * the score field was always honest (sum of fired signals = 0), but
 * displaying it alongside such a verdict reads as a bug to the user.
 */
function buildVerdictSection(result, style) {
  var section = CardService.newCardSection();

  var badge =
    "<b><font color=\"" + style.color + "\">" +
    style.icon + " " + style.label +
    "</font></b>";

  var text = style.hideScore
    ? badge
    : badge + "          Score: " + Math.round(result.score) + "/100";

  section.addWidget(CardService.newTextParagraph().setText(text));

  return section;
}

/**
 * Explanation / summary text.
 */
function buildSummarySection(explanation) {
  var section = CardService.newCardSection().setHeader("Summary");

  section.addWidget(
    CardService.newTextParagraph().setText(explanation)
  );

  return section;
}

/**
 * Top signals with severity, category, summary, and contribution.
 */
function buildFindingsSection(signals) {
  var section = CardService.newCardSection().setHeader("Top Findings");

  signals.forEach(function (signal) {
    section.addWidget(buildSignalWidget(signal));
  });

  return section;
}

/**
 * Single signal rendered as a DecoratedText widget.
 */
function buildSignalWidget(signal) {
  var severityLabel = signal.severity.toUpperCase();
  var categoryLabel = signal.category.replace(/_/g, " ").toUpperCase();
  var contribution = "+" + signal.score_contribution.toFixed(1) + " pts";

  return CardService.newDecoratedText()
    .setTopLabel(categoryLabel + "  ·  " + severityLabel)
    .setText(signal.summary)
    .setWrapText(true)
    .setBottomLabel(contribution);
}

/**
 * Collapsible limitations section — what the analysis did not check.
 */
function buildBlindSpotsSection(blindSpots) {
  var section = CardService.newCardSection()
    .setHeader("Limitations (" + blindSpots.length + ")")
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0);

  blindSpots.forEach(function (blindSpot) {
    section.addWidget(
      CardService.newDecoratedText()
        .setText(blindSpot.risk_note)
        .setWrapText(true)
        .setBottomLabel(blindSpot.reason)
    );
  });

  return section;
}

/**
 * Collapsible analysis scope section showing what ran.
 */
function buildScopeSection(scope) {
  var section = CardService.newCardSection()
    .setHeader("Analysis Scope")
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0);

  var lines = formatScopeLines(scope);

  section.addWidget(
    CardService.newTextParagraph().setText(lines.join("\n"))
  );

  return section;
}

/**
 * Formats scope info into human-readable lines.
 */
function formatScopeLines(scope) {
  var lines = [];

  if (scope.analyzers_run.length > 0) {
    lines.push("Analyzers: " + scope.analyzers_run.join(", "));
  } else {
    lines.push("Analyzers: none (skeleton mode)");
  }

  lines.push(
    "HTML: " + (scope.has_html ? "yes" : "no") +
    "  |  Attachments: " + (scope.has_attachments ? "yes" : "no") +
    "  |  Auth headers: " + (scope.has_auth_headers ? "yes" : "no")
  );

  return lines;
}

function buildReanalyzeSection(messageId) {
  var section = CardService.newCardSection();

  var action = CardService.newAction()
    .setFunctionName("onReanalyze")
    .setParameters({ messageId: messageId });

  section.addWidget(
    CardService.newTextButton()
      .setText("↻ Re-analyze")
      .setOnClickAction(action)
  );

  return section;
}

/**
 * Error card — shown when the backend is unreachable.
 */
function buildErrorCard(messageId) {
  var cardBuilder = CardService.newCardBuilder();

  var section = CardService.newCardSection();
  section.addWidget(
    CardService.newTextParagraph().setText("<b>Analysis Unavailable</b>")
  );
  section.addWidget(
    CardService.newTextParagraph().setText(
      "Could not reach the analysis backend. " +
      "This does not mean the email is safe."
    )
  );

  var retryAction = CardService.newAction()
    .setFunctionName("onReanalyze")
    .setParameters({ messageId: messageId });

  section.addWidget(
    CardService.newTextButton()
      .setText("↻ Retry")
      .setOnClickAction(retryAction)
  );

  cardBuilder.addSection(section);
  return cardBuilder.build();
}
