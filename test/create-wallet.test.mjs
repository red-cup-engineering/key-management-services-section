import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Wallet } from "ethers";
import { createWallet } from "../scripts/create-wallet.mjs";
import { PrivateKey } from "@red-cup-engineering/hive-blockchain-client-service/keys.mjs";

function tempRoots() {
  const home = mkdtempSync(join(tmpdir(), "key-management-home-"));
  const backupRoot = mkdtempSync(join(tmpdir(), "key-management-backup-"));
  const journalRoot = mkdtempSync(join(tmpdir(), "key-management-journal-"));
  return { home, backupRoot, journalRoot };
}

test("createWallet refuses without a passphrase", async () => {
  const { home, backupRoot, journalRoot } = tempRoots();
  const result = await createWallet({ id: "test-base-wallet", chain: "base", owner: "org", role: "pool", passphrase: undefined, backupRoot, home, credentialsDirectory: home, journalRoot });
  assert.equal(result.created, false);
  assert.match(result.reason, /KEY_PASSPHRASE is not set/u);
  rmSync(home, { recursive: true, force: true });
  rmSync(backupRoot, { recursive: true, force: true });
  rmSync(journalRoot, { recursive: true, force: true });
});

test("createWallet refuses without a backup root", async () => {
  const { home, backupRoot, journalRoot } = tempRoots();
  const result = await createWallet({ id: "test-base-wallet", chain: "base", owner: "org", role: "pool", passphrase: "a".repeat(20), backupRoot: undefined, home, credentialsDirectory: home, journalRoot });
  assert.equal(result.created, false);
  assert.match(result.reason, /KEY_BACKUP_ROOT is not set/u);
  rmSync(home, { recursive: true, force: true });
  rmSync(backupRoot, { recursive: true, force: true });
  rmSync(journalRoot, { recursive: true, force: true });
});

test("createWallet: EVM (base) round trip -- dual-copy custody, mode 0600, decrypt agreement, no duplicate id", async () => {
  const { home, backupRoot, journalRoot } = tempRoots();
  const registryPath = join(journalRoot, "registry.json");
  const passphrase = "correct horse battery staple!!";
  try {
    const result = await createWallet({ id: "tidepool-pool-base", chain: "base", owner: "org", role: "pool", relations: [{ kind: "consumed-by", target: "pool-service" }], passphrase, backupRoot, home, credentialsDirectory: home, registryPath, journalRoot });
    assert.equal(result.created, true);
    assert.equal(result.chain, "base");
    assert.match(result.address, /^0x[0-9a-fA-F]{40}$/u);
    assert.ok(result.receipt, "a receipt id must be returned");

    assert.equal((statSync(result.custody.locator).mode & 0o777).toString(8), "600");
    assert.equal((statSync(result.backup.locator).mode & 0o777).toString(8), "600");

    const primaryWallet = await Wallet.fromEncryptedJson(readFileSync(result.custody.locator, "utf8"), passphrase);
    const backupWallet = await Wallet.fromEncryptedJson(readFileSync(result.backup.locator, "utf8"), passphrase);
    assert.equal(primaryWallet.address, result.address);
    assert.equal(backupWallet.address, result.address);

    const registry = JSON.parse(readFileSync(registryPath, "utf8"));
    assert.equal(registry.wallets.length, 1);
    assert.equal(registry.wallets[0].address, result.address);
    assert.equal(registry.wallets[0].id, undefined);
    assert.equal(registry.wallets[0].role, "pool");
    assert.equal(registry.wallets[0].label, null);

    const sidecar = JSON.parse(readFileSync(result.metaPath, "utf8"));
    assert.equal(sidecar.id, "tidepool-pool-base");
    assert.equal(sidecar.owner, "org");
    assert.equal(sidecar.role, "pool");
    assert.deepEqual(sidecar.relations, [{ kind: "consumed-by", target: "pool-service" }]);
    assert.ok(sidecar.createdAt);

    const duplicateId = await createWallet({ id: "tidepool-pool-base", chain: "base", owner: "org", role: "pool", passphrase, backupRoot, home, credentialsDirectory: home, registryPath, journalRoot });
    assert.equal(duplicateId.created, false);
    assert.match(duplicateId.reason, /a key already exists at/u);
  } finally {
    rmSync(home, { recursive: true, force: true });
    rmSync(backupRoot, { recursive: true, force: true });
    rmSync(journalRoot, { recursive: true, force: true });
  }
});

test("createWallet: Hive round trip -- WIF primary/backup parse to the same public key", async () => {
  const { home, backupRoot, journalRoot } = tempRoots();
  const passphrase = "unused-for-hive-but-required!!";
  try {
    const result = await createWallet({ id: "test-hive-wallet", chain: "hive", owner: "org", role: "auxiliary", passphrase, backupRoot, home, credentialsDirectory: home, journalRoot });
    assert.equal(result.created, true);
    assert.equal(result.chain, "hive");
    assert.equal(result.address, "test-hive-wallet");
    assert.match(result.custody.reference, /^STM/u);

    const primaryAddress = PrivateKey.from(readFileSync(result.custody.locator, "utf8").trim()).createPublic().toString();
    const backupAddress = PrivateKey.from(readFileSync(result.backup.locator, "utf8").trim()).createPublic().toString();
    assert.equal(primaryAddress, result.custody.reference);
    assert.equal(backupAddress, result.custody.reference);
    assert.equal((statSync(result.custody.locator).mode & 0o777).toString(8), "600");
  } finally {
    rmSync(home, { recursive: true, force: true });
    rmSync(backupRoot, { recursive: true, force: true });
    rmSync(journalRoot, { recursive: true, force: true });
  }
});

test("createWallet refuses an unsupported chain", async () => {
  const { home, backupRoot, journalRoot } = tempRoots();
  const result = await createWallet({ id: "test-solana-wallet", chain: "solana", owner: "org", role: "auxiliary", passphrase: "x".repeat(20), backupRoot, home, credentialsDirectory: home, journalRoot });
  assert.equal(result.created, false);
  assert.match(result.reason, /chain solana is not supported/u);
  rmSync(home, { recursive: true, force: true });
  rmSync(backupRoot, { recursive: true, force: true });
  rmSync(journalRoot, { recursive: true, force: true });
});
