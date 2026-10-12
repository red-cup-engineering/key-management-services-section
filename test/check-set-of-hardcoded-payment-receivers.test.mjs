import assert from "node:assert/strict";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { DEFAULT_ALLOWLIST_PATHS, findHardcodedPaymentReceivers, readFilesUnderDirectory } from "../scripts/check-set-of-hardcoded-payment-receivers.mjs";

test("classifies an EVM address in a receiver field", () => {
  const rows = findHardcodedPaymentReceivers({ files: [{ path: "a.json", content: '{"receiver":"0x224C08A8526751887a83e2711B167f890c6D078d"}' }] });
  assert.equal(rows[0].kind, "evm-address");
});

test("classifies a Hive account name in a receiver field", () => {
  const rows = findHardcodedPaymentReceivers({ files: [{ path: "a.json", content: '{"receiver":"emsenn0"}' }] });
  assert.equal(rows[0].kind, "hive-account");
});

test("never classifies an over-short or punctuation-only value", () => {
  assert.deepEqual(findHardcodedPaymentReceivers({ files: [{ path: "a.json", content: '{"receiver":"ab"}' }] }), []);
  assert.deepEqual(findHardcodedPaymentReceivers({ files: [{ path: "a.json", content: '{"receiver":"---"}' }] }), []);
});

test("finds a JSON receiver field literal with path and line", () => {
  const files = [{ path: "a/tip-endpoints.json", content: '{"id":"x",\n"receiver":"emsenn0"}' }];
  const rows = findHardcodedPaymentReceivers({ files });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].field, "receiver");
  assert.equal(rows[0].kind, "hive-account");
  assert.equal(rows[0].line, 2);
});

test("finds an EVM address in a payTo field in a .mjs file", () => {
  const files = [{ path: "a/config.mjs", content: 'export const payTo = "0x224C08A8526751887a83e2711B167f890c6D078d";' }];
  const rows = findHardcodedPaymentReceivers({ files });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].kind, "evm-address");
});

test("never flags a non-receiver field", () => {
  const files = [{ path: "a/config.json", content: '{"comment": "0x224C08A8526751887a83e2711B167f890c6D078d"}' }];
  assert.deepEqual(findHardcodedPaymentReceivers({ files }), []);
});

test("never scans an unlisted extension", () => {
  const files = [{ path: "a/notes.txt", content: '{"receiver":"emsenn0"}' }];
  assert.deepEqual(findHardcodedPaymentReceivers({ files }), []);
});

test("excludes an allowlisted path", () => {
  const files = [{ path: "key-management-services-section/test/fixtures/example.json", content: '{"receiver":"emsenn0"}' }];
  assert.deepEqual(findHardcodedPaymentReceivers({ files, allowlistPaths: ["key-management-services-section/test/fixtures/"] }), []);
});

test("this section's own test fixture is excluded under its documented allowlist path", () => {
  const files = readFilesUnderDirectory(new URL("fixtures", import.meta.url).pathname);
  const rows = findHardcodedPaymentReceivers({ files, allowlistPaths: DEFAULT_ALLOWLIST_PATHS });
  assert.deepEqual(rows, []);
});

test("readFilesUnderDirectory skips a dangling symlink rather than crashing the whole walk", () => {
  const tempDirectory = mkdtempSync(join(tmpdir(), "check-hardcoded-payment-receivers-symlink-test-"));
  try {
    symlinkSync(join(tempDirectory, "does-not-exist.json"), join(tempDirectory, "broken-link.json"));
    writeFileSync(join(tempDirectory, "config.json"), '{"receiver":"emsenn0"}', "utf8");
    const files = readFilesUnderDirectory(tempDirectory);
    assert.equal(files.length, 1);
    assert.match(files[0].path, /config\.json$/u);
  } finally {
    rmSync(tempDirectory, { recursive: true, force: true });
  }
});

test("readFilesUnderDirectory walks a real directory and the checker still finds a non-allowlisted receiver", () => {
  const tempDirectory = mkdtempSync(join(tmpdir(), "check-hardcoded-payment-receivers-test-"));
  try {
    writeFileSync(join(tempDirectory, "config.json"), '{"receiver":"emsenn0"}', "utf8");
    const files = readFilesUnderDirectory(tempDirectory);
    assert.equal(files.length, 1);
    const rows = findHardcodedPaymentReceivers({ files, allowlistPaths: DEFAULT_ALLOWLIST_PATHS });
    assert.equal(rows.length, 1);
    assert.equal(rows[0].kind, "hive-account");
  } finally {
    rmSync(tempDirectory, { recursive: true, force: true });
  }
});
