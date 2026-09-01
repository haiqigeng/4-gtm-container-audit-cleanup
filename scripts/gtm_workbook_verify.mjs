#!/usr/bin/env node
/** Verify workbook structure, formulas, privacy, row fidelity, and rendered output. */

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
const { FileBlob, SpreadsheetFile } = await import(
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
  return crypto
    .createHash("sha256")
    .update(JSON.stringify(stableObject(value)), "utf8")
    .digest("hex");
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

function equal(actual, expected) {
  return JSON.stringify(actual) === JSON.stringify(expected);
}

function populated(matrix) {
  return (matrix || []).flat().filter((value) => value !== null && value !== "" && value !== undefined);
}

function privacyIssues(value) {
  const text = String(value ?? "");
  const issues = [];
  if (/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(text)) issues.push("email_address");
  if (/\b[A-Z]:\\Users\\[^\\\s]+/i.test(text) || /(?:^|\s)\/(?:home|Users)\/[^/\s]+/i.test(text)) {
    issues.push("local_user_path");
  }
  if (/(?:api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|authorization)\s*[:=]\s*(?!<redacted>)[^\s,;]+/i.test(text)) {
    issues.push("possible_secret");
  }
  return issues;
}

function parseNdjson(value) {
  return String(value || "")
    .split(/\r?\n/)
    .filter((line) => line.trim())
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return { unparsed: line };
      }
    });
}

function containsExactString(value, expected) {
  if (value === expected) return true;
  if (Array.isArray(value)) return value.some((child) => containsExactString(child, expected));
  if (value && typeof value === "object") {
    return Object.values(value).some((child) => containsExactString(child, expected));
  }
  return false;
}

async function main() {
  const packageArg = process.argv[2];
  if (!packageArg) throw new Error("Usage: gtm_workbook_verify.mjs <package-dir>");
  const packageDir = path.resolve(packageArg);
  await assertSafePackageRoot(packageDir);
  const deliveryDir = path.join(packageDir, "delivery");
  const currentPath = path.join(deliveryDir, "current-build.json");
  const current = JSON.parse(await fs.readFile(currentPath, "utf8"));
  const unsignedCurrent = { ...current };
  delete unsignedCurrent.current_build_sha256;
  const errors = [];
  if (stableHash(unsignedCurrent) !== current.current_build_sha256) {
    errors.push("current workbook build pointer hash is invalid");
  }
  const buildDir = path.join(deliveryDir, current.build_path);
  const manifestPath = path.join(buildDir, "workbook-build-manifest.json");
  const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8"));
  const unsignedManifest = { ...manifest };
  delete unsignedManifest.workbook_build_manifest_sha256;
  if (stableHash(unsignedManifest) !== manifest.workbook_build_manifest_sha256) {
    errors.push("workbook build manifest content hash is invalid");
  }
  if (manifest.workbook_build_manifest_sha256 !== current.workbook_build_manifest_sha256) {
    errors.push("current pointer is bound to another workbook build manifest");
  }
  if (stableHash(manifest.normalized_model) !== manifest.normalized_workbook_sha256) {
    errors.push("normalized workbook model hash is invalid");
  }
  if (manifest.normalized_workbook_sha256 !== manifest.recovery_normalized_workbook_sha256) {
    errors.push("recovery rebuild did not reproduce normalized workbook content");
  }
  const workbookPath = path.join(packageDir, manifest.workbook_path);
  if ((await fileHash(workbookPath)) !== manifest.workbook_file_sha256) {
    errors.push("workbook file changed after build");
  }
  const workbook = await SpreadsheetFile.importXlsx(await FileBlob.load(workbookPath));
  const expectedSheets = manifest.visible_sheets;
  const actualSheets = workbook.worksheets.items.map((sheet) => sheet.name);
  if (!equal(actualSheets, expectedSheets)) {
    errors.push(`visible workbook sheets differ: ${JSON.stringify(actualSheets)}`);
  }

  const privacyFindings = [];
  const rendererArtifacts = [];
  const rowChecks = [];
  const expectedComments = manifest.normalized_model.comments || [];
  for (const comment of expectedComments) {
    const expectedHash = stableHash({
      sheet: comment.sheet,
      cell: comment.cell,
      text: comment.text,
    });
    if (comment.comment_sha256 !== expectedHash) {
      errors.push(`${comment.sheet}!${comment.cell}: normalized comment hash is invalid`);
    }
    for (const issue of privacyIssues(comment.text)) {
      privacyFindings.push({
        sheet: comment.sheet,
        cell: comment.cell,
        surface: "comment_model",
        issue,
      });
    }
  }
  for (const sheetModel of manifest.normalized_model.sheets) {
    const sheet = workbook.worksheets.getItem(sheetModel.name);
    const actualNavigation = sheet.getRangeByIndexes(3, 0, 1, 1).values[0][0];
    if (actualNavigation !== sheetModel.nav) {
      errors.push(`${sheetModel.name}: navigation text differs from the build manifest`);
    }
    if (sheetModel.headers) {
      const headerRange = sheet.getRangeByIndexes(4, 0, 1, sheetModel.headers.length);
      if (!equal(headerRange.values[0], sheetModel.headers)) {
        errors.push(`${sheetModel.name}: table headers differ from the build manifest`);
      }
      for (const row of sheetModel.rows) {
        const actual = sheet.getRangeByIndexes(
          row.row_number - 1,
          0,
          1,
          sheetModel.headers.length,
        ).values[0];
        const pass = equal(actual, row.values);
        rowChecks.push({
          row_id: row.row_id,
          sheet: sheetModel.name,
          row_number: row.row_number,
          status: pass ? "pass" : "mismatch",
        });
        if (!pass) errors.push(`${row.row_id}: delivered row values differ from the sealed build model`);
      }
      const expectedWidths = sheetModel.dimensions.columns;
      expectedWidths.forEach((expected, index) => {
        const actual = sheet.getRangeByIndexes(0, index, 1, 1).format.columnWidth;
        if (Math.abs(Number(actual) - Number(expected)) > 0.25) {
          errors.push(`${sheetModel.name}: column ${index + 1} width changed`);
        }
      });
    }
    const used = sheet.getUsedRange();
    const values = used ? used.values : [];
    for (const value of populated(values)) {
      if (/HYPERLINK is not implemented|linkLocation=.*HYPERLINK/i.test(String(value))) {
        rendererArtifacts.push({ sheet: sheetModel.name, value: String(value).slice(0, 240) });
      }
      for (const issue of privacyIssues(value)) {
        privacyFindings.push({ sheet: sheetModel.name, issue });
      }
    }
    const formulas = used ? populated(used.formulas) : [];
    for (const formula of formulas) {
      errors.push(`${sheetModel.name}: unexpected formula found: ${formula}`);
    }
  }
  if (rendererArtifacts.length) {
    errors.push(`workbook contains ${rendererArtifacts.length} visible renderer artifact(s)`);
  }
  if (privacyFindings.length) {
    errors.push(`workbook privacy scan found ${privacyFindings.length} issue(s)`);
  }
  const threadInspection = await workbook.inspect({
    kind: "thread",
    summary: "verify every imported workbook comment",
    maxChars: 500000,
  });
  const threadRecords = parseNdjson(threadInspection.ndjson);
  const commentChecks = expectedComments.map((comment) => {
    const matchingRecords = threadRecords.filter((record) =>
      containsExactString(record, comment.text),
    );
    const locationVisible = matchingRecords.some(
      (record) =>
        containsExactString(record, comment.sheet) &&
        (containsExactString(record, comment.cell) ||
          containsExactString(record, `${comment.sheet}!${comment.cell}`)),
    );
    const status = matchingRecords.length === 1 && locationVisible ? "pass" : "mismatch";
    if (status !== "pass") {
      errors.push(`${comment.sheet}!${comment.cell}: imported comment text or location differs`);
    }
    return {
      sheet: comment.sheet,
      cell: comment.cell,
      comment_sha256: comment.comment_sha256,
      matching_records: matchingRecords.length,
      location_visible: locationVisible,
      status,
    };
  });
  const importedExpectedCommentRecords = threadRecords.filter((record) =>
    expectedComments.some((comment) => containsExactString(record, comment.text)),
  );
  if (importedExpectedCommentRecords.length !== expectedComments.length) {
    errors.push(
      `imported workbook comment count differs: expected ${expectedComments.length}, found ${importedExpectedCommentRecords.length}`,
    );
  }
  const formulaErrors = await workbook.inspect({
    kind: "match",
    searchTerm: "#REF!|#DIV/0!|#VALUE!|#NAME\\?|#N/A",
    options: { useRegex: true, maxResults: 300 },
    summary: "final formula error scan",
    maxChars: 12000,
  });
  const formulaErrorText = String(formulaErrors.ndjson || "");
  const formulaErrorMatches = formulaErrorText
    .split(/\r?\n/)
    .filter((line) => /#REF!|#DIV\/0!|#VALUE!|#NAME\?|#N\/A/.test(line));
  if (formulaErrorMatches.length) errors.push("workbook contains a formula error value");

  const verificationPreviewDir = path.join(buildDir, "verification-previews");
  await fs.mkdir(verificationPreviewDir, { recursive: true });
  const renderChecks = [];
  for (const sheetName of expectedSheets) {
    const preview = await workbook.render({
      sheetName,
      autoCrop: "all",
      scale: 1,
      format: "png",
    });
    const previewPath = path.join(
      verificationPreviewDir,
      `${sheetName.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase()}.png`,
    );
    const bytes = new Uint8Array(await preview.arrayBuffer());
    await fs.writeFile(previewPath, bytes);
    if (bytes.length < 500) errors.push(`${sheetName}: verification render is empty or corrupt`);
    renderChecks.push({
      sheet: sheetName,
      path: path.relative(packageDir, previewPath).replaceAll("\\", "/"),
      bytes: bytes.length,
      sha256: await fileHash(previewPath),
    });
  }
  const report = {
    kind: "gtm_analyst_workbook_technical_verification",
    schema_version: 1,
    status: errors.length ? "blocked" : "pass",
    workbook_file_sha256: manifest.workbook_file_sha256,
    workbook_build_manifest_sha256: manifest.workbook_build_manifest_sha256,
    sheet_order: actualSheets,
    row_checks: rowChecks,
    formula_error_matches: formulaErrorMatches,
    renderer_artifacts: rendererArtifacts,
    privacy_findings: privacyFindings,
    comment_checks: commentChecks,
    thread_inspection_sha256: stableHash(threadRecords),
    render_checks: renderChecks,
    errors,
  };
  report.technical_verification_sha256 = stableHash(report);
  await fs.writeFile(
    path.join(buildDir, "technical-verification.json"),
    `${JSON.stringify(report, null, 2)}\n`,
    "utf8",
  );
  process.stdout.write(`${JSON.stringify({ status: report.status, errors })}\n`);
  if (errors.length) process.exitCode = 2;
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 2;
});
