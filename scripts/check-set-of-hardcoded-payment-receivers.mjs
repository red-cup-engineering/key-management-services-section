#!/usr/bin/env node
/**
 * Finds every literal payment-receiver value sitting in a receiver-shaped field across a
 * directory or a named list of files (2026-09-05 ruling, payment-receivers-are-parameters-
 * never-literals: a payment receiver is never a literal in code, config, content, or a data
 * row). The exported operation is pure -- it takes already-read `{path, content}` pairs;
 * walking a directory and reading files live in this file's `import.meta.main` block only.
 * The only exclusions are this section's own derived storage
 * (`key-management-services-section/data/records/`) and this section's own test fixtures
 * (`key-management-services-section/test/fixtures/`), the documented allowlist paths.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const SCANNED_EXTENSIONS = Object.freeze([".mjs", ".mts", ".json", ".jsonc", ".toml", ".html", ".md"]);
const FIELD_NAMES = Object.freeze(["receiver", "payTo", "to", "address", "account", "lnurl", "X402_PAY_TO"]);
const RECEIVER_FIELD_PATTERN = new RegExp(`["'\`]?\\b(${FIELD_NAMES.join("|")})\\b["'\`]?\\s*[:=]\\s*(?:"([^"]*)"|'([^']*)'|\`([^\`]*)\`)`, "gu");
const EVM_ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/u;
const HIVE_ACCOUNT_PATTERN = /^[a-z][a-z0-9.-]{2,15}$/u;
const LIGHTNING_ADDRESS_PATTERN = /^[a-z0-9._-]+@[a-z0-9.-]+\.[a-z]{2,}$/iu;
const LNURL_PATTERN = /^lnurl1[a-z0-9]{20,}$/iu;
const DEFAULT_EXCLUDED_DIRECTORIES = new Set(["node_modules", ".git", "dist", "build", "coverage", ".tmp"]);

/** Documented allowlist paths: this package's own derived registry storage and test fixtures. */
export const DEFAULT_ALLOWLIST_PATHS = Object.freeze([
  "key-management-services-section/data/records/",
  "key-management-services-section/test/fixtures/",
]);

/**
 * Classifies a candidate literal as one of the four payment-receiver shapes this checker
 * recognizes, or `null` when it matches none of them. A module-internal helper -- the
 * operation's one export is `findHardcodedPaymentReceivers`.
 * @param {string} value
 * @returns {(("evm-address"|"lightning-address"|"lnurl"|"hive-account")|null)}
 */
function classifyReceiverLiteral(value) {
  const trimmed = String(value).trim();
  if (EVM_ADDRESS_PATTERN.test(trimmed)) return "evm-address";
  if (LNURL_PATTERN.test(trimmed)) return "lnurl";
  if (LIGHTNING_ADDRESS_PATTERN.test(trimmed)) return "lightning-address";
  if (trimmed.length >= 3 && HIVE_ACCOUNT_PATTERN.test(trimmed)) return "hive-account";
  return null;
}

function isScannedPath(path) {
  return SCANNED_EXTENSIONS.some((extension) => path.endsWith(extension));
}

function isAllowlisted(path, allowlistPaths) {
  return allowlistPaths.some((prefix) => path.includes(prefix));
}

/** @typedef {{path: string, line: number, field: string, value: string, kind: string}} HardcodedReceiverRow */
/**
 * Finds every literal payment-receiver value sitting in a receiver-shaped field across a set of
 * already-read files, excluding allowlisted paths. Pure with respect to the filesystem: the
 * caller supplies file contents and never this operation.
 * @param {{files: readonly {path: string, content: string}[], allowlistPaths?: readonly string[]}} input
 * @returns {readonly HardcodedReceiverRow[]}
 */
export function findHardcodedPaymentReceivers({ files, allowlistPaths = [] }) {
  const rows = [];
  for (const { path, content } of files) {
    if (!isScannedPath(path) || isAllowlisted(path, allowlistPaths)) continue;
    const lines = content.split("\n");
    lines.forEach((line, index) => {
      RECEIVER_FIELD_PATTERN.lastIndex = 0;
      let match = RECEIVER_FIELD_PATTERN.exec(line);
      while (match) {
        const field = match[1];
        const value = match[2] ?? match[3] ?? match[4] ?? "";
        const kind = classifyReceiverLiteral(value);
        if (kind) rows.push({ path, line: index + 1, field, value, kind });
        match = RECEIVER_FIELD_PATTERN.exec(line);
      }
    });
  }
  return rows;
}

/**
 * Walks a directory recursively, reading every scanned-extension file into a `{path, content}`
 * pair. Skips `node_modules`, `.git`, `dist`, `build`, `coverage`, `.tmp` directories. A single
 * entry this host cannot stat or read (a dangling symlink, a permission-denied file, a socket,
 * a file removed mid-walk) is skipped rather than aborting the whole walk -- a 37GB tree with
 * one broken Emacs lock-file symlink must still be checked, never crash on it.
 * @param {string} root
 * @returns {readonly {path: string, content: string}[]}
 */
export function readFilesUnderDirectory(root) {
  const files = [];
  const walk = (directory) => {
    let names;
    try {
      names = readdirSync(directory);
    } catch {
      return;
    }
    for (const name of names) {
      if (DEFAULT_EXCLUDED_DIRECTORIES.has(name)) continue;
      const path = join(directory, name);
      let stat;
      try {
        stat = statSync(path);
      } catch {
        continue;
      }
      if (stat.isDirectory()) walk(path);
      else if (stat.isFile() && isScannedPath(path)) {
        try {
          files.push({ path, content: readFileSync(path, "utf8") });
        } catch {
          continue;
        }
      }
    }
  };
  walk(root);
  return files;
}

if (import.meta.main) {
  const { positionals } = await import("node:util").then(({ parseArgs }) => parseArgs({ allowPositionals: true }));
  if (positionals.length === 0) {
    process.stderr.write("usage: check-set-of-hardcoded-payment-receivers.mjs <file-or-directory> [<file-or-directory> ...]\n");
    process.exit(2);
  }
  const files = positionals.flatMap((target) => (statSync(target).isDirectory() ? readFilesUnderDirectory(target) : [{ path: target, content: readFileSync(target, "utf8") }]));
  const rows = findHardcodedPaymentReceivers({ files, allowlistPaths: DEFAULT_ALLOWLIST_PATHS });
  process.stdout.write(`${JSON.stringify(rows, null, 2)}\n`);
  if (rows.length > 0) process.exitCode = 1;
}
