#!/usr/bin/env node
/** Build, render, and export the single analyst-facing GTM audit workbook. */

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const artifactNodeModules = process.env.CODEX_ARTIFACT_NODE_MODULES;
if (!artifactNodeModules || !path.isAbsolute(artifactNodeModules)) {
  throw new Error(
    "CODEX_ARTIFACT_NODE_MODULES must be the absolute bundled workspace node_modules path",
  );
}
const { SpreadsheetFile, Workbook } = await import(
  pathToFileURL(
    path.join(
      artifactNodeModules,
      "@oai",
      "artifact-tool",
      "dist",
      "artifact_tool.mjs",
    ),
  ).href
);

const PRIORITY_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3, None: 4 };
const PALETTE = {
  navy: "#17324D",
  teal: "#167D8D",
  paleTeal: "#E8F4F5",
  blue: "#2C5F8A",
  paleBlue: "#EAF1F7",
  amber: "#D88A18",
  paleAmber: "#FFF3D9",
  red: "#B5483F",
  paleRed: "#FBEAE8",
  green: "#3E7A59",
  paleGreen: "#EAF4ED",
  gray: "#5B6570",
  paleGray: "#F2F4F6",
  line: "#D8DEE4",
  white: "#FFFFFF",
  ink: "#1E2933",
};

function stableObject(value) {
  if (Array.isArray(value)) return value.map(stableObject);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, stableObject(value[key])]),
    );
  }
  return value;
}

function stableHash(value) {
  const serialized = JSON.stringify(stableObject(value));
  return crypto.createHash("sha256").update(serialized, "utf8").digest("hex");
}

async function fileHash(filePath) {
  return crypto.createHash("sha256").update(await fs.readFile(filePath)).digest("hex");
}

async function assertSafePackageRoot(packageDir) {
  const stats = await fs.lstat(packageDir);
  if (stats.isSymbolicLink()) {
    throw new Error("audit package root is a link or reparse point");
  }
  const pending = [packageDir];
  while (pending.length) {
    const directory = pending.pop();
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      const entryPath = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        throw new Error(`audit package path is a link or reparse point: ${entryPath}`);
      }
      if (entry.isDirectory()) pending.push(entryPath);
    }
  }
}

function safeText(value) {
  if (value === null || value === undefined) return "";
  const text = typeof value === "string" ? value : JSON.stringify(value);
  const trimmed = text.replace(/^\s+/, "");
  return /^[=+\-@\t\r\n]/.test(trimmed) ? `'${text}` : text;
}

function matrix(rows) {
  return rows.map((row) => row.map(safeText));
}

function styleTitle(sheet, range, title) {
  range.merge();
  range.values = [[safeText(title)]];
  range.format = {
    fill: PALETTE.navy,
    font: { bold: true, color: PALETTE.white, size: 18 },
    verticalAlignment: "center",
    wrapText: true,
  };
  range.format.rowHeight = 34;
}

function styleSubtitle(range, subtitle) {
  range.merge();
  range.values = [[safeText(subtitle)]];
  range.format = {
    fill: PALETTE.paleBlue,
    font: { color: PALETTE.navy, italic: true, size: 10 },
    verticalAlignment: "center",
    wrapText: true,
    borders: { preset: "outside", style: "thin", color: PALETTE.line },
  };
  range.format.rowHeight = 30;
}

function styleHeaders(range) {
  range.format = {
    fill: PALETTE.teal,
    font: { bold: true, color: PALETTE.white, size: 10 },
    wrapText: true,
    verticalAlignment: "center",
    borders: {
      bottom: { style: "medium", color: PALETTE.navy },
    },
  };
  range.format.rowHeight = 30;
}

function styleData(range) {
  range.format = {
    font: { color: PALETTE.ink, size: 9 },
    wrapText: true,
    verticalAlignment: "top",
    borders: {
      insideHorizontal: { style: "thin", color: PALETTE.line },
    },
  };
}

function addNavigation(sheet, sheetNames, width) {
  if (!sheetNames.length || width < 1) return "";
  const navigationText = `Sections — use workbook tabs: ${sheetNames
    .map((name) => (name === sheet.name ? `${name} (current)` : name))
    .join("  |  ")}`;
  const range = sheet.getRangeByIndexes(3, 0, 1, width);
  range.merge();
  range.values = [[safeText(navigationText)]];
  range.format = {
    fill: PALETTE.paleGray,
    font: { color: PALETTE.blue, size: 9, italic: true },
    horizontalAlignment: "left",
    wrapText: true,
    borders: { preset: "outside", style: "thin", color: PALETTE.line },
  };
  range.format.rowHeight = 22;
  return navigationText;
}

function priorityFill(priority) {
  if (priority === "Critical" || priority === "High") return PALETTE.paleRed;
  if (priority === "Medium") return PALETTE.paleAmber;
  if (priority === "Low") return PALETTE.paleBlue;
  return PALETTE.paleGray;
}

function decisionFill(label) {
  if (label === "Needs correction") return PALETTE.paleRed;
  if (label === "Optimisation") return PALETTE.paleAmber;
  if (label === "Appropriate as configured") return PALETTE.paleGreen;
  if (label === "Decision needed") return PALETTE.paleBlue;
  return PALETTE.paleGray;
}

function tableName(sheetName) {
  return `GTM_${sheetName.replace(/[^A-Za-z0-9]/g, "_")}`;
}

function addTableIfRows(sheet, startRow, columnCount, rowCount) {
  if (!rowCount) return;
  const endRow = startRow + rowCount;
  const endColumn = String.fromCharCode(64 + columnCount);
  const table = sheet.tables.add(
    `A${startRow}:${endColumn}${endRow}`,
    true,
    tableName(sheet.name),
  );
  table.style = "TableStyleMedium2";
  table.showBandedColumns = false;
  table.showFilterButton = true;
}

function rowEditorialIndex(editorial) {
  return new Map(editorial.rows.map((row) => [row.row_id, row]));
}

function mappedRows(deliveryMap, sheetName) {
  return deliveryMap.rows.filter((row) => row.primary_sheet === sheetName);
}

function previewRange(sheetModel) {
  const columnCount = sheetModel.dimensions.columns.length;
  const endColumn = String.fromCharCode(64 + columnCount);
  const endRow = sheetModel.name === "01 Overview"
    ? 50
    : Math.min(30, 5 + Math.max((sheetModel.rows || []).length, 1));
  return `A1:${endColumn}${endRow}`;
}

function addTechnicalComment(workbook, sheet, cellAddress, row, model) {
  const operationNote = {
    operation_id: row.locked.operation_id,
    source_decision_ids: row.locked.source_decision_ids,
    subject_keys: row.locked.subject_keys,
    depends_on: row.locked.depends_on,
    exact_target_state: row.locked.exact_target_state,
    actions: row.locked.technical_note,
    action_payload_sha256: row.locked.action_payload_sha256,
  };
  const auditNote = {
    decision_id: row.locked.decision_id,
    subject_keys: row.locked.subject_keys,
    area_id: row.locked.area_id,
    audit_focus: row.locked.audit_focus,
    decision_class: row.locked.decision_class,
    operation_id: row.locked.operation_id,
  };
  const heading = row.primary_sheet === "02 Recommendations"
    ? "Technical operation detail"
    : "Exact row identifiers";
  const note = row.primary_sheet === "02 Recommendations" ? operationNote : auditNote;
  const text = `${heading}\n${JSON.stringify(note, null, 2)}`;
  workbook.comments.addThread(
    { cell: sheet.getRange(cellAddress) },
    text,
  );
  model.comments.push({
    sheet: sheet.name,
    cell: cellAddress,
    text,
    comment_sha256: stableHash({ sheet: sheet.name, cell: cellAddress, text }),
  });
}

function buildOverview(workbook, deliveryMap, editorial, model) {
  const sheet = workbook.worksheets.getItem("01 Overview");
  const overview = { ...deliveryMap.overview, ...editorial.overview_prose };
  styleTitle(sheet, sheet.getRange("A1:H1"), "GTM container audit and optimisation");
  styleSubtitle(sheet.getRange("A2:H2"), overview.container_label);
  const nav = addNavigation(sheet, deliveryMap.visible_sheets, 8);
  sheet.getRange("A6:H6").merge();
  sheet.getRange("A6:H6").values = [[safeText(overview.audit_status)]];
  sheet.getRange("A6:H6").format = {
    fill: PALETTE.paleTeal,
    font: { bold: true, color: PALETTE.teal, size: 11 },
    wrapText: true,
    borders: { preset: "outside", style: "thin", color: PALETTE.teal },
  };
  sheet.getRange("A8:H9").merge();
  sheet.getRange("A8:H9").values = [[safeText(overview.scope_boundary)]];
  sheet.getRange("A8:H9").format = {
    fill: PALETTE.paleGray,
    font: { color: PALETTE.gray, size: 9 },
    wrapText: true,
    verticalAlignment: "top",
    borders: { preset: "outside", style: "thin", color: PALETTE.line },
  };

  const decisionRows = Object.entries(overview.decision_counts || {}).sort();
  const priorityRows = Object.entries(overview.priority_counts || {}).sort(
    (a, b) => (PRIORITY_RANK[a[0]] ?? 99) - (PRIORITY_RANK[b[0]] ?? 99),
  );
  sheet.getRange("A11:C11").values = [["Decision type", "Count", "Interpretation"]];
  styleHeaders(sheet.getRange("A11:C11"));
  if (decisionRows.length) {
    const values = decisionRows.map(([key, value]) => [
      overview.decision_labels?.[key] || key,
      value,
      overview.decision_meanings?.[key] || "See the detailed audit rows.",
    ]);
    sheet.getRangeByIndexes(11, 0, values.length, 3).values = matrix(values);
    styleData(sheet.getRangeByIndexes(11, 0, values.length, 3));
  }
  sheet.getRange("E11:G11").values = [["Priority", "Count", "Reading order"]];
  styleHeaders(sheet.getRange("E11:G11"));
  if (priorityRows.length) {
    const values = priorityRows.map(([key, value], index) => [key, value, index + 1]);
    sheet.getRangeByIndexes(11, 4, values.length, 3).values = matrix(values);
    styleData(sheet.getRangeByIndexes(11, 4, values.length, 3));
    values.forEach((row, index) => {
      sheet.getRangeByIndexes(11 + index, 4, 1, 3).format.fill = priorityFill(row[0]);
    });
  }
  const summaryStart = 13 + Math.max(decisionRows.length, priorityRows.length);
  const actionSummary = (overview.highest_value_actions || [])
    .map((value, index) => `${index + 1}. ${value}`)
    .join("\n") || "None";
  const summaryBlocks = [
    ["Highest-value actions", actionSummary, 5],
    ["Target architecture", overview.target_architecture_summary, 2],
    ["Important retained setup", overview.important_retained_summary, 2],
    ["Open decisions and evidence limits", overview.blocking_summary, 2],
    ["Next step", overview.next_step, 2],
  ];
  let summaryCursor = summaryStart;
  summaryBlocks.forEach(([label, value, valueRows], index) => {
    const row = summaryCursor;
    sheet.getRangeByIndexes(row - 1, 0, 1, 2).merge();
    sheet.getRangeByIndexes(row - 1, 0, 1, 2).values = [[safeText(label)]];
    sheet.getRangeByIndexes(row - 1, 0, 1, 2).format = {
      fill: PALETTE.navy,
      font: { bold: true, color: PALETTE.white, size: 10 },
    };
    sheet.getRangeByIndexes(row - 1, 2, valueRows, 6).merge();
    sheet.getRangeByIndexes(row - 1, 2, valueRows, 6).values = [[safeText(value)]];
    sheet.getRangeByIndexes(row - 1, 2, valueRows, 6).format = {
      fill: index === summaryBlocks.length - 1 ? PALETTE.paleAmber : PALETTE.white,
      font: { color: PALETTE.ink, size: 9 },
      wrapText: true,
      verticalAlignment: "top",
      borders: { preset: "outside", style: "thin", color: PALETTE.line },
    };
    summaryCursor += valueRows + 1;
  });
  const deltaStart = summaryCursor;
  sheet.getRangeByIndexes(deltaStart - 1, 0, 1, 4).values = [
    ["Material object-count changes", "Source", "Target", "Change"],
  ];
  styleHeaders(sheet.getRangeByIndexes(deltaStart - 1, 0, 1, 4));
  const deltas = overview.material_count_deltas || [];
  if (deltas.length) {
    sheet.getRangeByIndexes(deltaStart, 0, deltas.length, 4).values = matrix(
      deltas.map((row) => [row.metric, row.source, row.target, row.delta]),
    );
    styleData(sheet.getRangeByIndexes(deltaStart, 0, deltas.length, 4));
  } else {
    sheet.getRangeByIndexes(deltaStart, 0, 1, 4).merge();
    sheet.getRangeByIndexes(deltaStart, 0, 1, 4).values = [[
      "No material object-count change; configuration changes may still be proposed.",
    ]];
  }
  sheet.getRange("A:A").format.columnWidth = 24;
  sheet.getRange("B:B").format.columnWidth = 12;
  sheet.getRange("C:C").format.columnWidth = 28;
  sheet.getRange("D:D").format.columnWidth = 12;
  sheet.getRange("E:E").format.columnWidth = 20;
  sheet.getRange("F:F").format.columnWidth = 12;
  sheet.getRange("G:G").format.columnWidth = 18;
  sheet.getRange("H:H").format.columnWidth = 18;
  model.sheets.push({
    name: sheet.name,
    nav,
    overview,
    dimensions: { columns: [24, 12, 28, 12, 20, 12, 18, 18] },
  });
}

function buildDataSheet(workbook, deliveryMap, editorialIndex, config, model) {
  const sheet = workbook.worksheets.getItem(config.name);
  const rows = mappedRows(deliveryMap, config.name);
  styleTitle(sheet, sheet.getRangeByIndexes(0, 0, 1, config.headers.length), config.title);
  styleSubtitle(
    sheet.getRangeByIndexes(1, 0, 1, config.headers.length),
    config.subtitle,
  );
  const nav = addNavigation(sheet, deliveryMap.visible_sheets, config.headers.length);
  sheet.getRangeByIndexes(4, 0, 1, config.headers.length).values = [config.headers];
  styleHeaders(sheet.getRangeByIndexes(4, 0, 1, config.headers.length));
  const values = rows.map((mapped) => {
    const editorial = editorialIndex.get(mapped.row_id);
    if (!editorial) throw new Error(`Missing editorial row ${mapped.row_id}`);
    return config.values(mapped, editorial.prose).map(safeText);
  });
  if (values.length) {
    sheet.getRangeByIndexes(5, 0, values.length, config.headers.length).values = values;
    styleData(sheet.getRangeByIndexes(5, 0, values.length, config.headers.length));
    values.forEach((_value, index) => {
      const mapped = rows[index];
      const priority = String(mapped.locked.priority || "None");
      const label = String(mapped.locked.human_decision_label || "");
      sheet.getRangeByIndexes(5 + index, 0, 1, config.headers.length).format.fill =
        label ? decisionFill(label) : priorityFill(priority);
      addTechnicalComment(workbook, sheet, `A${6 + index}`, mapped, model);
    });
    addTableIfRows(sheet, 5, config.headers.length, values.length);
  } else {
    sheet.getRangeByIndexes(5, 0, 1, config.headers.length).merge();
    sheet.getRangeByIndexes(5, 0, 1, config.headers.length).values = [[
      safeText(config.emptyMessage),
    ]];
    sheet.getRangeByIndexes(5, 0, 1, config.headers.length).format = {
      fill: PALETTE.paleGreen,
      font: { color: PALETTE.green, italic: true },
      wrapText: true,
    };
  }
  config.widths.forEach((width, index) => {
    sheet.getRangeByIndexes(0, index, Math.max(6 + values.length, 10), 1).format.columnWidth = width;
  });
  sheet.freezePanes.freezeRows(5);
  sheet.showGridLines = false;
  model.sheets.push({
    name: sheet.name,
    headers: config.headers,
    rows: rows.map((row, index) => ({
      row_id: row.row_id,
      row_number: 6 + index,
      binding_sha256: row.binding_sha256,
      locked: row.locked,
      values: values[index] || [],
    })),
    nav,
    dimensions: { columns: config.widths },
  });
}

async function buildWorkbook(deliveryMap, editorial, commentAuthor = "User") {
  const workbook = Workbook.create();
  deliveryMap.visible_sheets.forEach((name) => workbook.worksheets.add(name));
  workbook.comments.setSelf({ displayName: commentAuthor });
  const editorialIndex = rowEditorialIndex(editorial);
  const model = {
    schema_version: 1,
    visible_sheets: deliveryMap.visible_sheets,
    delivery_map_sha256: deliveryMap.delivery_map_sha256,
    sheets: [],
    comments: [],
  };
  for (const sheetName of deliveryMap.visible_sheets) {
    workbook.worksheets.getItem(sheetName).showGridLines = false;
  }
  buildOverview(workbook, deliveryMap, editorial, model);
  buildDataSheet(
    workbook,
    deliveryMap,
    editorialIndex,
    {
      name: "02 Recommendations",
      title: "Recommendations",
      subtitle: "Every decision-ready operation appears once. A cell note on the action contains its structured technical detail.",
      headers: [
        "Action + operation ID",
        "Finding type + priority",
        "Affected scope",
        "Current setup",
        "Why it matters",
        "Recommended target",
        "Analyst decision / implementation handoff",
        "Static verification / rollback",
      ],
      values: (_row, prose) => [
        prose.action_operation_id,
        prose.finding_type_priority,
        prose.affected_scope,
        prose.current_setup,
        prose.why_it_matters,
        prose.recommended_target,
        prose.analyst_handoff,
        prose.verification_rollback,
      ],
      widths: [28, 22, 34, 42, 40, 42, 40, 42],
      emptyMessage: "No decision-ready operation is proposed.",
    },
    model,
  );
  buildDataSheet(
    workbook,
    deliveryMap,
    editorialIndex,
    {
      name: "03 Decisions Needed",
      title: "Decisions needed",
      subtitle: "Each row asks for one owner answer and explains what that answer unlocks.",
      headers: [
        "Decision ID",
        "Question",
        "Why this is needed",
        "Recommendation",
        "Affected scope",
        "What the answer unlocks",
      ],
      values: (row, prose) => [
        row.locked.decision_id,
        prose.question,
        prose.why_needed,
        prose.recommendation,
        prose.affected_scope,
        prose.answer_unlocks,
      ],
      widths: [22, 40, 38, 38, 34, 38],
      emptyMessage: "No owner decision is currently required.",
    },
    model,
  );
  buildDataSheet(
    workbook,
    deliveryMap,
    editorialIndex,
    {
      name: "04 Full Audit",
      title: "Full audit",
      subtitle: "Complete reconciled coverage, including configurations that should remain as they are.",
      headers: [
        "Audit ID",
        "Area",
        "Affected scope",
        "Decision",
        "Plain-language finding",
        "Outcome / linked action",
        "Priority",
        "Evidence confidence",
      ],
      values: (row, prose) => [
        row.locked.decision_id,
        `${row.locked.area_id} — ${row.locked.area_title}\nFocus: ${row.locked.audit_focus}`,
        prose.affected_scope,
        row.locked.human_decision_label,
        prose.plain_finding,
        prose.outcome_linked_action,
        row.locked.priority,
        row.locked.confidence,
      ],
      widths: [22, 34, 34, 28, 52, 42, 14, 20],
      emptyMessage: "No semantic audit decision was produced; this indicates an invalid delivery map.",
    },
    model,
  );
  if (deliveryMap.visible_sheets.includes("05 Custom Code")) {
    buildDataSheet(
      workbook,
      deliveryMap,
      editorialIndex,
      {
        name: "05 Custom Code",
        title: "Custom code review",
        subtitle: "Container-visible behavior and the safest source-supported target for each applicable code conclusion.",
        headers: [
          "Audit ID",
          "Affected code scope",
          "Current behavior",
          "Finding",
          "Safest target",
          "Linked action",
          "Priority",
          "Evidence confidence",
        ],
        values: (row, prose) => [
          row.locked.decision_id,
          prose.affected_scope,
          prose.current_behavior,
          prose.finding,
          prose.safest_target,
          prose.linked_action,
          row.locked.priority,
          row.locked.confidence,
        ],
        widths: [22, 34, 46, 42, 44, 38, 14, 20],
        emptyMessage: "No custom-code conclusion applies.",
      },
      model,
    );
  }
  return { workbook, model };
}

async function main() {
  const [packageArg, outputArg, commentAuthorArg] = process.argv.slice(2);
  if (packageArg === "--preflight") {
    process.stdout.write(
      `${JSON.stringify({ status: "pass", runtime: "workspace_spreadsheet_artifact" })}\n`,
    );
    return;
  }
  if (!packageArg) {
    throw new Error(
      "Usage: gtm_workbook_build.mjs --preflight | <package-dir> [output.xlsx] [comment-author]",
    );
  }
  const packageDir = path.resolve(packageArg);
  await assertSafePackageRoot(packageDir);
  const deliveryDir = path.join(packageDir, "delivery");
  const mapPath = path.join(deliveryDir, "delivery-map.json");
  const mapSealPath = path.join(deliveryDir, "delivery-map-seal.json");
  const editorialPath = path.join(deliveryDir, "editorial.json");
  const editorialSealPath = path.join(deliveryDir, "editorial-seal.json");
  const [deliveryMap, mapSeal, editorial, editorialSeal] = await Promise.all(
    [mapPath, mapSealPath, editorialPath, editorialSealPath].map(async (filePath) =>
      JSON.parse(await fs.readFile(filePath, "utf8")),
    ),
  );
  if (editorial.status !== "complete" || editorialSeal.validator_status !== "pass") {
    throw new Error("A completed, sealed editorial artifact is required before workbook build");
  }
  if (mapSeal.validator_status !== "pass") {
    throw new Error("The delivery map is not sealed by a passing validator");
  }
  const unsignedMap = { ...deliveryMap };
  delete unsignedMap.delivery_map_sha256;
  if (stableHash(unsignedMap) !== deliveryMap.delivery_map_sha256) {
    throw new Error("Delivery map content hash is invalid");
  }
  if ((await fileHash(mapPath)) !== mapSeal.delivery_map_file_sha256) {
    throw new Error("Delivery map changed after sealing");
  }
  if ((await fileHash(editorialPath)) !== editorialSeal.editorial_file_sha256) {
    throw new Error("Editorial artifact changed after sealing");
  }
  const sequence = Number(editorialSeal.amendment_sequence || 0);
  const buildDir = outputArg
    ? path.dirname(path.resolve(outputArg))
    : path.join(deliveryDir, "builds", `build-${String(sequence).padStart(3, "0")}`);
  const outputPath = path.resolve(outputArg || path.join(buildDir, "gtm-container-audit.xlsx"));
  const outputRelative = path.relative(packageDir, outputPath);
  if (
    !outputRelative ||
    outputRelative.startsWith(`..${path.sep}`) ||
    outputRelative === ".." ||
    path.isAbsolute(outputRelative)
  ) {
    throw new Error("Workbook output must remain inside the audit package");
  }
  try {
    await fs.access(outputPath);
    throw new Error(`Workbook build output already exists: ${outputPath}`);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const first = await buildWorkbook(deliveryMap, editorial, commentAuthorArg || "User");
  const recovery = await buildWorkbook(deliveryMap, editorial, commentAuthorArg || "User");
  const firstModelHash = stableHash(first.model);
  const recoveryModelHash = stableHash(recovery.model);
  if (firstModelHash !== recoveryModelHash) {
    throw new Error("Recovery rebuild produced different normalized workbook content");
  }
  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  const exported = await SpreadsheetFile.exportXlsx(first.workbook);
  await exported.save(outputPath);
  const previewDir = path.join(buildDir, "previews");
  await fs.mkdir(previewDir, { recursive: true });
  const previews = [];
  for (const sheetName of deliveryMap.visible_sheets) {
    const sheetModel = first.model.sheets.find((sheet) => sheet.name === sheetName);
    if (!sheetModel) throw new Error(`Missing normalized model for ${sheetName}`);
    const range = previewRange(sheetModel);
    const preview = await first.workbook.render({
      sheetName,
      range,
      autoCrop: "all",
      scale: 1,
      format: "png",
    });
    const previewPath = path.join(
      previewDir,
      `${sheetName.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}.png`,
    );
    await fs.writeFile(previewPath, new Uint8Array(await preview.arrayBuffer()));
    previews.push({
      sheet: sheetName,
      range,
      path: path.relative(packageDir, previewPath).replaceAll("\\", "/"),
      sha256: await fileHash(previewPath),
    });
  }
  const manifest = {
    kind: "gtm_analyst_workbook_build_manifest",
    schema_version: 1,
    delivery_map_sha256: deliveryMap.delivery_map_sha256,
    editorial_file_sha256: await fileHash(editorialPath),
    editorial_seal_sha256: editorialSeal.editorial_seal_sha256,
    editorial_amendment_sequence: sequence,
    workbook_path: path.relative(packageDir, outputPath).replaceAll("\\", "/"),
    workbook_file_sha256: await fileHash(outputPath),
    normalized_workbook_sha256: firstModelHash,
    recovery_normalized_workbook_sha256: recoveryModelHash,
    visible_sheets: deliveryMap.visible_sheets,
    normalized_model: first.model,
    previews,
    status: "built_and_rendered",
  };
  manifest.workbook_build_manifest_sha256 = stableHash(manifest);
  await fs.writeFile(
    path.join(buildDir, "workbook-build-manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
    "utf8",
  );
  const currentBuild = {
    kind: "gtm_current_workbook_build",
    schema_version: 1,
    build_path: path.relative(deliveryDir, buildDir).replaceAll("\\", "/"),
    editorial_seal_sha256: editorialSeal.editorial_seal_sha256,
    workbook_build_manifest_sha256: manifest.workbook_build_manifest_sha256,
  };
  currentBuild.current_build_sha256 = stableHash(currentBuild);
  await fs.writeFile(
    path.join(deliveryDir, "current-build.json"),
    `${JSON.stringify(currentBuild, null, 2)}\n`,
    "utf8",
  );
  process.stdout.write(
    `${JSON.stringify({
      status: "pass",
      workbook: outputPath,
      visible_sheets: deliveryMap.visible_sheets,
      normalized_workbook_sha256: firstModelHash,
      previews: previews.length,
    })}\n`,
  );
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 2;
});
