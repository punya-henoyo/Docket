// Default help behind the i, per kind. The backend's kit_help.py holds the same sentences for the property sheet.
export const KIT_HELP: Readonly<Record<string, string>> = {
  'henoyo-facet-panel':
    'Which slices of the list exist, how many rows each, and what is showing now. Each value is a checkbox with its count; a value with no rows stays, dimmed. Groups fold, and Clear all removes every filter. A group can carry a phrase such as owned by {values} so the active-filters line reads in words; without one it reads Label: values.',
  'henoyo-record-banner':
    'What needs attention on this record and why. Each line names its level and the rule behind it; a link beside it takes the next step.',
  'henoyo-board':
    'What is in each state, who owns it and how old it is. Move a card with its Move to menu or by dragging; a column marked decision only opens the decision dialog instead.',
  'henoyo-evidence-ledger':
    'The evidence attached here, one file per row. Each row says when it expires and whether a reviewer accepted it; expired files come first.',
  'henoyo-stepper':
    'Where you are in a multi-step form. The current step is marked, a step that needs attention says so, and the last step lists your answers with an Edit link before you submit.',
  'henoyo-summary-detail':
    'The list and the open item, side by side. Each row names its status in words; choose a row to read its fields, and use the action when the item has one.',
  'henoyo-approval-chain':
    'Who has approved this record and who is next. Read the steps in order; the highlighted step is the one waiting.',
  'henoyo-status-path':
    'Where this record is in its lifecycle. Ticks are done, the filled step is current, and a hatched Decision step (only where a status records a decision) is still to come.',
  'henoyo-visual-picker':
    'Which option applies. Each card explains the choice; the selected card is filled, with a tick and the word Selected. A value set only by a decision opens the decision dialog.',
  'henoyo-person-chip':
    'Who this is and their role here. The name is always written out; the initials are only a mark, and a dashed mark means nobody is assigned.',
  'henoyo-deadline-clock':
    'How long is left on each deadline. Bars run from the start date, the line marks now, and a red bar is overdue.',
  'henoyo-matrix':
    'Which cells are covered. Red cells are missing, amber ones are partly met and plain ones are met; hatched cells do not apply.',
  'henoyo-record-timeline':
    'What happened to this record, and when. Newest first; select a dot to jump to the event.',
  'henoyo-ring':
    'How a whole splits into parts. The largest part is highlighted; the legend gives each count and share.',
  'henoyo-heatmap':
    'Where the counts are highest. Darker cells hold more records; hover or focus a cell for its count.',
  'henoyo-report-heatmap':
    'Where the counts are highest. Darker cells hold more records; hover or focus a cell for its count.',
  'henoyo-report-ring':
    'How a whole splits into parts. The largest part is highlighted; the legend gives each count and share.',
  'henoyo-lineage-graph':
    'Where data comes from and where it goes. Boxes are records, and arrows follow the flow with the label on the line.',
  'henoyo-exposure-tree':
    'What this record is exposed to. Open a branch to see the records beneath it.',
  'henoyo-unit-grid':
    'How many records sit in each severity. One square is one record, and the legend gives the counts.',
  'henoyo-loss-exceedance':
    'How often a loss of a given size is expected. Read across from a probability to the loss on the curve.',
  'henoyo-risk-ledger':
    'Which rows carry the most. Bars are ranked highest first, and the top three are highlighted.',
  'henoyo-periodic-table':
    'Where the work sits on the grid you laid out. Filled tiles have records; select one to see them.',
  'henoyo-rank-gauge':
    'How each row ranks against the typical one. Bars above the median are highlighted.',
  'henoyo-narrative': 'The report in one sentence, with the biggest items listed under it.',
  'henoyo-severity-age':
    'How many records of each severity have been open for how long. Darker cells hold more.',
  'henoyo-discovery-trend':
    'How the count has changed over time. Each colour is a band; the legend gives the latest values.',
  'henoyo-kpi-bar': 'Which values are largest. Bars are ranked, and the longest is highlighted.',
  'henoyo-relationship-fanout':
    'What this record connects to. Each ring is one hop, and colour shows the type of record.',
  'henoyo-blast-radius':
    'How far a problem reaches from this record. Each ring is one more hop, and the nearest is highlighted.',
  'henoyo-zone-exposure':
    'How much crosses between zones. Rows are where it starts and columns where it ends; darker is larger.',
  'henoyo-zone-enclosure':
    'Which zone each record sits in. A line shows when one record points at another.',
};
