import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { randomBytes } from "node:crypto";
import { Mnemonic, Wallet } from "ethers";
import { createWallet } from "../scripts/create-wallet.mjs";
import { verifyLocalEnvVariable, verifyLocalKeystoreFile, verifyWalletCustody } from "../scripts/verify-set-of-wallet-custody.mjs";
import { deriveEvmAddressesFromMnemonic } from "../src/derive-key-material.mjs";
import { buildWalletRegistry } from "../src/wallet-registry.mjs";

function throwawayMnemonic(entropyBytes = 16) {
  return Mnemonic.fromEntropy(randomBytes(entropyBytes)).phrase;
}

test("verifyWalletCustody: a freshly created EVM wallet verifies agreed with its passphrase", async () => {
  const home = mkdtempSync(join(tmpdir(), "key-management-home-"));
  const backupRoot = mkdtempSync(join(tmpdir(), "key-management-backup-"));
  const journalRoot = mkdtempSync(join(tmpdir(), "key-management-journal-"));
  const passphrase = "verify test passphrase 12345!!";
  try {
    const created = await createWallet({ id: "verify-base-wallet", chain: "base", owner: "org", role: "pool", passphrase, backupRoot, home, journalRoot });
    assert.equal(created.created, true);
    const registry = buildWalletRegistry({
      derivedAt: "2026-09-05T00:00:00Z",
      wallets: [{ chain: "base", address: created.address, owner: "org", role: "pool", relations: [], custody: created.custody, balanceReader: null, label: null, sources: [], lastSeen: "2026-09-05T00:00:00Z" }],
    });
    const result = await verifyWalletCustody({
      registry,
      localHostname: "bare-cedar-fog",
      checkLocalKeystore: (wallet) => verifyLocalKeystoreFile(wallet, { passphrase, backupRoot }),
      checkRemoteKeystore: () => { throw new Error("must not be called for a local wallet"); },
      checkEnvOnHost: () => { throw new Error("must not be called for a keystore-file row"); },
    });
    assert.deepEqual(result.counts, { agreed: 1, mismatch: 0, missing: 0 });
    assert.equal(result.rows[0].status, "agreed");
    assert.equal(result.rows[0].address, created.address);
    assert.equal(result.rows[0].custodyKind, "keystore-file");
  } finally {
    rmSync(home, { recursive: true, force: true });
    rmSync(backupRoot, { recursive: true, force: true });
    rmSync(journalRoot, { recursive: true, force: true });
  }
});

test("verifyWalletCustody: a missing keystore file is reported missing, not thrown", async () => {
  const registry = buildWalletRegistry({
    derivedAt: "2026-09-05T00:00:00Z",
    wallets: [{ chain: "base", address: "0x0000000000000000000000000000000000000003", owner: "org", role: "pool", relations: [], custody: { kind: "keystore-file", host: "bare-cedar-fog", locator: "/nonexistent/path.json" }, balanceReader: null, label: null, sources: [], lastSeen: "2026-09-05T00:00:00Z" }],
  });
  const result = await verifyWalletCustody({
    registry,
    localHostname: "bare-cedar-fog",
    checkLocalKeystore: (wallet) => verifyLocalKeystoreFile(wallet, {}),
    checkRemoteKeystore: () => { throw new Error("unreachable"); },
    checkEnvOnHost: () => { throw new Error("unreachable"); },
  });
  assert.equal(result.rows[0].status, "missing");
  assert.equal(result.counts.missing, 1);
});

test("verifyWalletCustody: unknown custody is reported missing, never guessed", async () => {
  const registry = buildWalletRegistry({
    derivedAt: "2026-09-05T00:00:00Z",
    wallets: [{ chain: "hive", address: "emsenn0", owner: "founder", role: "treasury", relations: [], custody: { kind: "unknown", host: null, locator: null }, balanceReader: null, label: null, sources: [], lastSeen: "2026-09-05T00:00:00Z" }],
  });
  const result = await verifyWalletCustody({
    registry,
    checkLocalKeystore: () => { throw new Error("unreachable"); },
    checkRemoteKeystore: () => { throw new Error("unreachable"); },
    checkEnvOnHost: () => { throw new Error("unreachable"); },
  });
  assert.equal(result.rows[0].status, "missing");
  assert.match(result.rows[0].detail, /not independently verifiable/u);
});

test("verifyWalletCustody: a remote keystore-file row is dispatched to the remote checker", async () => {
  const registry = buildWalletRegistry({
    derivedAt: "2026-09-05T00:00:00Z",
    wallets: [{ chain: "hive", address: "michael561", owner: "enterprise:aagaard", role: "signer", relations: [], custody: { kind: "keystore-file", host: "cold-red-gate", locator: "~/.config/blockchain/hive/michael561/active.wif" }, balanceReader: null, label: null, sources: [], lastSeen: "2026-09-05T00:00:00Z" }],
  });
  const result = await verifyWalletCustody({
    registry,
    localHostname: "bare-cedar-fog",
    checkLocalKeystore: () => { throw new Error("must not be called for a remote wallet"); },
    checkRemoteKeystore: () => ({ status: "agreed", detail: "exists on cold-red-gate at mode 600" }),
    checkEnvOnHost: () => { throw new Error("unreachable"); },
  });
  assert.equal(result.rows[0].status, "agreed");
});

test("verifyWalletCustody: a remote env-on-host row is dispatched to the remote env checker", async () => {
  const registry = buildWalletRegistry({
    derivedAt: "2026-09-05T00:00:00Z",
    wallets: [{ chain: "ethereum", address: "0x0000000000000000000000000000000000000004", owner: "org", role: "signer", relations: [], custody: { kind: "env-on-host", host: "cold-red-gate", locator: "SOME_SIGNER_KEY" }, balanceReader: null, label: null, sources: [], lastSeen: "2026-09-05T00:00:00Z" }],
  });
  const result = await verifyWalletCustody({
    registry,
    localHostname: "bare-cedar-fog",
    checkLocalKeystore: () => { throw new Error("unreachable"); },
    checkRemoteKeystore: () => { throw new Error("unreachable"); },
    checkEnvOnHost: () => ({ status: "missing", detail: "SOME_SIGNER_KEY is not set on cold-red-gate" }),
  });
  assert.equal(result.rows[0].status, "missing");
  assert.equal(result.counts.missing, 1);
});

test("verifyWalletCustody: a local env-on-host row is re-derived in memory, never over SSH", async () => {
  const wallet = Wallet.createRandom();
  const registry = buildWalletRegistry({
    derivedAt: "2026-09-05T00:00:00Z",
    wallets: [{ chain: "base", address: wallet.address, owner: "org", role: "auxiliary", relations: [], custody: { kind: "env-on-host", host: "bare-cedar-fog", locator: "TEST_EVM_KEY" }, balanceReader: null, label: null, sources: [], lastSeen: "2026-09-05T00:00:00Z" }],
  });
  const result = await verifyWalletCustody({
    registry,
    localHostname: "bare-cedar-fog",
    checkLocalKeystore: () => { throw new Error("unreachable"); },
    checkRemoteKeystore: () => { throw new Error("unreachable"); },
    checkEnvOnHost: () => { throw new Error("must not be called for a local env row"); },
    checkLocalEnv: (row) => verifyLocalEnvVariable(row, { env: { TEST_EVM_KEY: wallet.privateKey } }),
  });
  assert.equal(result.rows[0].status, "agreed");
});

test("verifyWalletCustody: a mnemonic-derived env-on-host row re-derives at its own derivationPath and agrees", async () => {
  const phrase = throwawayMnemonic();
  const [{ address, derivationPath }] = deriveEvmAddressesFromMnemonic(phrase, { count: 1 });
  const registry = buildWalletRegistry({
    derivedAt: "2026-09-05T00:00:00Z",
    wallets: [{
      chain: "base", address, owner: "founder", role: "treasury", relations: [],
      custody: { kind: "env-on-host", host: "bare-cedar-fog", locator: "A_SEED_PHRASE", derivationPath },
      balanceReader: null, label: null, sources: [], lastSeen: "2026-09-05T00:00:00Z",
    }],
  });
  const result = await verifyWalletCustody({
    registry,
    localHostname: "bare-cedar-fog",
    checkLocalKeystore: () => { throw new Error("unreachable"); },
    checkRemoteKeystore: () => { throw new Error("unreachable"); },
    checkEnvOnHost: () => { throw new Error("must not be called for a local env row"); },
    checkLocalEnv: (row) => verifyLocalEnvVariable(row, { env: { A_SEED_PHRASE: phrase } }),
  });
  assert.deepEqual(result.counts, { agreed: 1, mismatch: 0, missing: 0 });
  assert.equal(result.rows[0].status, "agreed");
  assert.ok(!JSON.stringify(result).includes(phrase));
});

test("verifyLocalEnvVariable: a mnemonic row honors a companion <locator>_PASSPHRASE variable", () => {
  const phrase = throwawayMnemonic();
  const [{ address, derivationPath }] = deriveEvmAddressesFromMnemonic(phrase, { passphrase: "a throwaway test passphrase", count: 1 });
  const result = verifyLocalEnvVariable(
    { chain: "base", address, custody: { locator: "A_SEED_PHRASE", reference: null, derivationPath } },
    { env: { A_SEED_PHRASE: phrase, A_SEED_PHRASE_PASSPHRASE: "a throwaway test passphrase" } },
  );
  assert.equal(result.status, "agreed");
});

test("verifyLocalEnvVariable: a mnemonic row with no recorded derivationPath is reported missing, never guessed", () => {
  const phrase = throwawayMnemonic();
  const [{ address }] = deriveEvmAddressesFromMnemonic(phrase, { count: 1 });
  const result = verifyLocalEnvVariable(
    { chain: "base", address, custody: { locator: "A_SEED_PHRASE", reference: null, derivationPath: null } },
    { env: { A_SEED_PHRASE: phrase } },
  );
  assert.equal(result.status, "missing");
});

test("verifyLocalEnvVariable never echoes the raw value in its detail on a mismatch", () => {
  const otherWallet = Wallet.createRandom();
  const result = verifyLocalEnvVariable(
    { chain: "base", address: "0x0000000000000000000000000000000000000005", custody: { locator: "TEST_EVM_KEY", reference: null } },
    { env: { TEST_EVM_KEY: otherWallet.privateKey } },
  );
  assert.equal(result.status, "mismatch");
  assert.ok(!result.detail.includes(otherWallet.privateKey));
});
