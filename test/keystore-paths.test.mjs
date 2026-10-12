import assert from "node:assert/strict";
import test from "node:test";
import { backupKeyPath, backupKeyPathForLocator, configRoot, extensionForChain, keyPath, metaPath } from "../src/keystore-paths.mjs";

test("extensionForChain: json for EVM chains; Hive keys are not keystore files", () => {
  assert.equal(extensionForChain("base"), "json");
  assert.equal(extensionForChain("ethereum"), "json");
  assert.throws(() => extensionForChain("hive"), /chain hive is not supported/u);
});

test("extensionForChain rejects an unsupported chain", () => {
  assert.throws(() => extensionForChain("solana"), /chain solana is not supported/u);
});

test("configRoot is this process's credentials directory, or the directory given", () => {
  const saved = process.env.CREDENTIALS_DIRECTORY;
  process.env.CREDENTIALS_DIRECTORY = "/run/user/1/credentials";
  try {
    assert.equal(configRoot(), "/run/user/1/credentials");
    assert.equal(configRoot({ directory: "/tmp/test-credentials" }), "/tmp/test-credentials");
  } finally {
    if (saved === undefined) delete process.env.CREDENTIALS_DIRECTORY; else process.env.CREDENTIALS_DIRECTORY = saved;
  }
});

test("configRoot refuses without a credentials directory, or gives null when optional", () => {
  const saved = process.env.CREDENTIALS_DIRECTORY;
  delete process.env.CREDENTIALS_DIRECTORY;
  try {
    assert.throws(() => configRoot(), /CREDENTIALS_DIRECTORY is not set/u);
    assert.equal(configRoot({ optional: true }), null);
  } finally {
    if (saved !== undefined) process.env.CREDENTIALS_DIRECTORY = saved;
  }
});

test("keyPath builds the canonical primary path", () => {
  assert.equal(keyPath({ configRoot: "/home/test/.config/561-group", chain: "base", id: "tidepool-pool-base" }), "/home/test/.config/561-group/keys/base/tidepool-pool-base.json");
});

test("keyPath rejects an id that is not lowercase kebab-case", () => {
  assert.throws(() => keyPath({ configRoot: "/x", chain: "base", id: "Tidepool" }), /must be lowercase kebab-case/u);
});

test("backupKeyPath mirrors keyPath under the backup root", () => {
  assert.equal(backupKeyPath({ backupRoot: "/mnt/backup", chain: "base", id: "tidepool-pool-base" }), "/mnt/backup/keys/base/tidepool-pool-base.json");
});

test("backupKeyPathForLocator re-roots a known primary path under the backup root by filename", () => {
  assert.equal(
    backupKeyPathForLocator({ backupRoot: "/mnt/backup", chain: "base", locator: "/home/x/.config/561-group/keys/base/tidepool-pool-base.json" }),
    "/mnt/backup/keys/base/tidepool-pool-base.json",
  );
});

test("metaPath builds the sidecar path beside the primary key file", () => {
  assert.equal(metaPath({ configRoot: "/home/test/.config/561-group", chain: "base", id: "tidepool-pool-base" }), "/home/test/.config/561-group/keys/base/tidepool-pool-base.meta.json");
});

test("metaPath rejects an id that is not lowercase kebab-case", () => {
  assert.throws(() => metaPath({ configRoot: "/x", chain: "base", id: "Tidepool" }), /must be lowercase kebab-case/u);
});
