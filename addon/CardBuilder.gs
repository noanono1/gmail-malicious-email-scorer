// INCONCLUSIVE is intentionally non-alarming: it means "we did not have
// enough coverage to judge", not "we judged this and it looked bad". The
// neutral gray + info glyph keeps the badge from reading like a finding.
// Score is hidden in this state because there was nothing to score; see
// buildVerdictSection.
// hideBar suppresses the score bar where it would amplify severity that
// the verdict doesn't carry — for SAFE the bar would render mostly empty
// and read as "incomplete" rather than reassuring.
var VERDICT_STYLES = {
  safe:             { color: "#1B8332", icon: "✓", label: "SAFE",             hideScore: false, hideBar: true  },
  inconclusive:     { color: "#5F6368", icon: "ⓘ", label: "INCONCLUSIVE",     hideScore: true,  hideBar: true  },
  suspicious:       { color: "#F9A825", icon: "⚠", label: "SUSPICIOUS",       hideScore: false, hideBar: false },
  likely_malicious: { color: "#E65100", icon: "⚠", label: "LIKELY MALICIOUS", hideScore: false, hideBar: false },
  malicious:        { color: "#C62828", icon: "✕", label: "MALICIOUS",        hideScore: false, hideBar: false },
  _unknown:         { color: "#757575", icon: "?", label: "UNKNOWN",          hideScore: true,  hideBar: true  },
};

// Display order is a narrative: who sent it → how it was authenticated →
// what's inside → where it points → what's attached. Categories with no
// fired signals are dropped during bucketing.
var CATEGORY_DISPLAY = [
  { key: "sender_identity", label: "Sender" },
  { key: "authentication",  label: "Authentication" },
  { key: "body_content",    label: "Content" },
  { key: "url_structure",   label: "Links" },
  { key: "attachment",      label: "Attachments" },
];

var SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/**
 * Builds the main analysis result card from the backend response.
 */
function buildAnalysisCard(result, messageId) {
  var verdictStyle = VERDICT_STYLES[result.verdict] || VERDICT_STYLES._unknown;
  var cardBuilder = CardService.newCardBuilder();

  cardBuilder.addSection(buildVerdictSection(result, verdictStyle));

  var hasFindings = result.top_signals && result.top_signals.length > 0;

  if (result.explanation && !hasFindings) {
    cardBuilder.addSection(buildSummarySection(result.explanation));
  }

  if (hasFindings) {
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

  section.addWidget(CardService.newTextParagraph().setText(badge));

  if (!style.hideScore) {
    var score = Math.round(result.score);
    var scoreHtml =
      "<b><font color=\"" + style.color + "\" size=\"6\">" + score + "</font></b>" +
      "<font color=\"#5F6368\"> / 100</font>";
    section.addWidget(CardService.newTextParagraph().setText(scoreHtml));
    if (!style.hideBar) {
      section.addWidget(
        CardService.newTextParagraph().setText(buildScoreBarHtml(score, style.color))
      );
    }
  }

  return section;
}

/**
 * 10-block bar where each block represents 10 points. Filled blocks share
 * the verdict color so the same severity reads the same anywhere on the
 * card; empty blocks use a light neutral gray.
 */
function buildScoreBarHtml(score, color) {
  var TOTAL_BLOCKS = 10;
  var filledCount = Math.max(0, Math.min(TOTAL_BLOCKS, Math.round(score / 10)));

  var filled = new Array(filledCount + 1).join("▓");
  var empty = new Array(TOTAL_BLOCKS - filledCount + 1).join("░");

  return "<font color=\"" + color + "\">" + filled + "</font>" +
         "<font color=\"#DADCE0\">" + empty + "</font>";
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
 * Top signals grouped by category. Category headers carry an aggregate
 * icon driven by the worst severity in the bucket; the per-signal widget
 * drops the now-redundant category label.
 */
function buildFindingsSection(signals) {
  var section = CardService.newCardSection()
    .setHeader("Top Findings (" + signals.length + ")");

  bucketSignalsByCategory(signals).forEach(function (bucket) {
    section.addWidget(buildCategoryHeaderWidget(bucket));
    bucket.signals.forEach(function (signal) {
      section.addWidget(buildSignalWidget(signal));
    });
  });

  return section;
}

/**
 * Buckets signals into CATEGORY_DISPLAY order, preserving incoming signal
 * order within each bucket and dropping empty categories. Each bucket
 * carries the max severity seen, used to drive the header glyph/color.
 */
function bucketSignalsByCategory(signals) {
  var byKey = {};
  CATEGORY_DISPLAY.forEach(function (entry) {
    byKey[entry.key] = { key: entry.key, label: entry.label, signals: [], maxSeverityRank: -1, maxSeverity: "info" };
  });

  signals.forEach(function (signal) {
    var bucket = byKey[signal.category];
    if (!bucket) return;
    bucket.signals.push(signal);
    var rank = SEVERITY_RANK[signal.severity];
    if (rank > bucket.maxSeverityRank) {
      bucket.maxSeverityRank = rank;
      bucket.maxSeverity = signal.severity;
    }
  });

  return CATEGORY_DISPLAY
    .map(function (entry) { return byKey[entry.key]; })
    .filter(function (bucket) { return bucket.signals.length > 0; });
}

/**
 * Category header — palette mirrors VERDICT_STYLES so the same severity
 * always reads the same colour anywhere on the card.
 */
function buildCategoryHeaderWidget(bucket) {
  var rank = bucket.maxSeverityRank;
  var style;
  if (rank >= SEVERITY_RANK.high) {
    style = { icon: "✕", color: "#C62828" };
  } else if (rank === SEVERITY_RANK.medium) {
    style = { icon: "⚠", color: "#F9A825" };
  } else {
    style = { icon: "ⓘ", color: "#5F6368" };
  }

  var html =
    "<b><font color=\"" + style.color + "\">" +
    style.icon + "  " + bucket.label +
    " (" + bucket.signals.length + ")" +
    "</font></b>";

  return CardService.newTextParagraph().setText(html);
}

/**
 * Single signal rendered as a DecoratedText widget. Category is implicit
 * from the surrounding bucket header, so the top label carries severity only.
 */
function buildSignalWidget(signal) {
  var severityLabel = signal.severity.toUpperCase();
  var contribution = "+" + signal.score_contribution.toFixed(1) + " pts";

  return CardService.newDecoratedText()
    .setTopLabel(severityLabel)
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

  lines.push("Analyzers: " + scope.analyzers_run.join(", "));

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
