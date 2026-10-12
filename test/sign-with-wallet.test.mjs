import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Mnemonic, Transaction, Wallet } from "ethers";
import { transfer } from "@red-cup-engineering/hive-blockchain-client-service/ops.mjs";
import { deriveEvmAddressFromMnemonicAtPath } from "../src/derive-key-material.mjs";
import { createWallet } from "../scripts/create-wallet.mjs";
import { signWithWallet } from "../scripts/sign-with-wallet.mjs";

function throwawayMnemonic() {
  return Mnemonic.fromEntropy(randomBytes(16)).phrase;
}

const evmTransactionOverrides = { nonce: 0, gasLimit: 21000n, maxFeePerGas: 1_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n, chainId: 8453, data: "0x" };

function tempRoots() {
  return {
    home: mkdtempSync(join(tmpdir(), "key-management-home-")),
    backupRoot: mkdtempSync(join(tmpdir(), "key-management-backup-")),
    journalRoot: mkdtempSync(join(tmpdir(), "key-management-journal-")),
  };
}

const evmMandate = {
  chain: "base",
  address: "0x0000000000000000000000000000000000000009",
  allowedContracts: ["0x0000000000000000000000000000000000000002"],
  maxAmountWei: "1000000000000000000",
  expiresAt: "2026-12-31T00:00:00Z",
};

test("signWithWallet refuses a payload outside the mandate without touching the keystore", async () => {
  const result = await signWithWallet({
    id: "tidepool-pool-base", chain: "base", mandate: evmMandate,
    payload: { chain: "base", contract: "0x0000000000000000000000000000000000000099", valueWei: "1" },
    keystorePath: "/nonexistent/path.json", passphrase: "irrelevant",
    now: "2026-09-05T00:00:00Z",
  });
  assert.equal(result.signed, false);
  assert.match(result.reason, /outside the mandate's allowed set/u);
});

test("signWithWallet signs an EVM transaction that satisfies its mandate", async () => {
  const { home, backupRoot, journalRoot } = tempRoots();
  const passphrase = "sign test passphrase 1234567!!";
  try {
    const wallet = await createWallet({ id: "tidepool-pool-base", chain: "base", owner: "org", role: "pool", passphrase, backupRoot, home, journalRoot });
    assert.equal(wallet.created, true);
    const payload = {
      chain: "base", contract: "0x0000000000000000000000000000000000000002", valueWei: "1",
      transaction: { nonce: 0, gasLimit: 21000n, maxFeePerGas: 1_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n, chainId: 8453, data: "0x" },
    };
    const result = await signWithWallet({ id: "tidepool-pool-base", chain: "base", mandate: { ...evmMandate, address: wallet.address }, payload, keystorePath: wallet.custody.locator, passphrase, now: "2026-09-05T00:00:00Z", journalRoot });
    assert.equal(result.signed, true);
    assert.match(result.signature, /^0x[0-9a-f]+$/u);
    assert.ok(result.receipt, "a receipt id must be returned");
  } finally {
    rmSync(home, { recursive: true, force: true });
    rmSync(backupRoot, { recursive: true, force: true });
    rmSync(journalRoot, { recursive: true, force: true });
  }
});

test("signWithWallet refuses an EVM sign without a passphrase", async () => {
  const payload = { chain: "base", contract: "0x0000000000000000000000000000000000000002", valueWei: "1", transaction: {} };
  const result = await signWithWallet({ id: "x", chain: "base", mandate: evmMandate, payload, keystorePath: "/nonexistent.json", passphrase: undefined, now: "2026-09-05T00:00:00Z" });
  assert.equal(result.signed, false);
  assert.match(result.reason, /KEY_PASSPHRASE is not set/u);
});

test("signWithWallet signs a Hive transfer that satisfies its mandate", async () => {
  const { home, backupRoot, journalRoot } = tempRoots();
  const passphrase = "unused for hive but required!!";
  try {
    const wallet = await createWallet({ id: "test-hive-signer", chain: "hive", owner: "org", role: "signer", passphrase, backupRoot, home, journalRoot });
    assert.equal(wallet.created, true);
    const hiveMandate = { chain: "hive", address: "test-hive-signer", allowedRecipients: ["sigmund-vexler"], maxAmountWei: "5000", expiresAt: "2026-12-31T00:00:00Z" };
    const tx = {
      ref_block_num: 1, ref_block_prefix: 1, expiration: "2026-09-05T00:10:00", extensions: [],
      operations: [transfer({ from: "test-hive-signer", to: "sigmund-vexler", amount: "5.000 HIVE" })],
    };
    const payload = { chain: "hive", recipient: "sigmund-vexler", amount: "5000", amountText: "5.000 HIVE", tx };
    const result = await signWithWallet({ id: "test-hive-signer", chain: "hive", mandate: hiveMandate, payload, hiveKeyRoot: join(home, ".config/blockchain/hive"), now: "2026-09-05T00:00:00Z", journalRoot });
    assert.equal(result.signed, true);
    assert.equal(result.signature.signatures.length, 1);
    assert.match(result.signature.signatures[0], /^[0-9a-f]{130}$/u);
  } finally {
    rmSync(home, { recursive: true, force: true });
    rmSync(backupRoot, { recursive: true, force: true });
    rmSync(journalRoot, { recursive: true, force: true });
  }
});

test("signWithWallet refuses a Hive payload whose tx does not match the mandate-checked recipient", async () => {
  const { home, backupRoot, journalRoot } = tempRoots();
  const passphrase = "unused for hive but required!!";
  try {
    const wallet = await createWallet({ id: "hive-signer-2", chain: "hive", owner: "org", role: "signer", passphrase, backupRoot, home, journalRoot });
    const hiveMandate = { chain: "hive", address: "hive-signer-2", allowedRecipients: ["sigmund-vexler"], maxAmountWei: "5000", expiresAt: "2026-12-31T00:00:00Z" };
    const tx = {
      ref_block_num: 1, ref_block_prefix: 1, expiration: "2026-09-05T00:10:00", extensions: [],
      operations: [transfer({ from: "hive-signer-2", to: "someone-else", amount: "5.000 HIVE" })],
    };
    const payload = { chain: "hive", recipient: "sigmund-vexler", amount: "100", amountText: "5.000 HIVE", tx };
    const result = await signWithWallet({ id: "hive-signer-2", chain: "hive", mandate: hiveMandate, payload, hiveKeyRoot: join(home, ".config/blockchain/hive"), now: "2026-09-05T00:00:00Z" });
    assert.equal(result.signed, false);
    assert.match(result.reason, /does not match payload.recipient/u);
  } finally {
    rmSync(home, { recursive: true, force: true });
    rmSync(backupRoot, { recursive: true, force: true });
    rmSync(journalRoot, { recursive: true, force: true });
  }
});

test("signWithWallet derives an env-on-host EVM wallet from a mnemonic at the recorded derivation path", async () => {
  const mnemonic = throwawayMnemonic();
  const derivationPath = "m/44'/60'/0'/0/0";
  const locator = "KEY_MANAGEMENT_TEST_MNEMONIC_1";
  process.env[locator] = mnemonic;
  try {
    const expectedAddress = deriveEvmAddressFromMnemonicAtPath(mnemonic, { path: derivationPath });
    const mandate = { chain: "base", address: expectedAddress, allowedContracts: ["0x0000000000000000000000000000000000000002"], maxAmountWei: "0", expiresAt: "2026-12-31T00:00:00Z" };
    const payload = { chain: "base", contract: "0x0000000000000000000000000000000000000002", valueWei: "0", transaction: evmTransactionOverrides };
    const result = await signWithWallet({
      chain: "base", mandate, payload, custody: { kind: "env-on-host", locator, derivationPath }, now: "2026-09-05T00:00:00Z",
    });
    assert.equal(result.signed, true);
    assert.equal(result.id, expectedAddress);
    assert.equal(Transaction.from(result.signature).from, expectedAddress);
  } finally {
    delete process.env[locator];
  }
});

test("signWithWallet honors the <locator>_PASSPHRASE companion variable for a mnemonic custody", async () => {
  const mnemonic = throwawayMnemonic();
  const derivationPath = "m/44'/60'/0'/0/1";
  const locator = "KEY_MANAGEMENT_TEST_MNEMONIC_2";
  process.env[locator] = mnemonic;
  process.env[`${locator}_PASSPHRASE`] = "an extra 25th word";
  try {
    const expectedAddress = deriveEvmAddressFromMnemonicAtPath(mnemonic, { path: derivationPath, passphrase: "an extra 25th word" });
    const withoutPassphraseAddress = deriveEvmAddressFromMnemonicAtPath(mnemonic, { path: derivationPath });
    assert.notEqual(expectedAddress, withoutPassphraseAddress, "the fixture must actually exercise the passphrase branch");
    const mandate = { chain: "base", address: expectedAddress, allowedContracts: ["0x0000000000000000000000000000000000000002"], maxAmountWei: "0", expiresAt: "2026-12-31T00:00:00Z" };
    const payload = { chain: "base", contract: "0x0000000000000000000000000000000000000002", valueWei: "0", transaction: evmTransactionOverrides };
    const result = await signWithWallet({
      chain: "base", mandate, payload, custody: { kind: "env-on-host", locator, derivationPath }, now: "2026-09-05T00:00:00Z",
    });
    assert.equal(result.signed, true);
    assert.equal(Transaction.from(result.signature).from, expectedAddress);
  } finally {
    delete process.env[locator];
    delete process.env[`${locator}_PASSPHRASE`];
  }
});

test("signWithWallet derives an env-on-host EVM wallet from a bare hex private key", async () => {
  const wallet = Wallet.createRandom();
  const locator = "KEY_MANAGEMENT_TEST_HEXKEY_1";
  process.env[locator] = wallet.privateKey;
  try {
    const mandate = { chain: "base", address: wallet.address, allowedContracts: ["0x0000000000000000000000000000000000000002"], maxAmountWei: "0", expiresAt: "2026-12-31T00:00:00Z" };
    const payload = { chain: "base", contract: "0x0000000000000000000000000000000000000002", valueWei: "0", transaction: evmTransactionOverrides };
    const result = await signWithWallet({
      chain: "base", mandate, payload, custody: { kind: "env-on-host", locator, derivationPath: null }, now: "2026-09-05T00:00:00Z",
    });
    assert.equal(result.signed, true);
    assert.equal(Transaction.from(result.signature).from, wallet.address);
  } finally {
    delete process.env[locator];
  }
});

test("signWithWallet refuses env-on-host custody when the named variable is not set", async () => {
  const locator = "KEY_MANAGEMENT_TEST_MISSING_VAR";
  delete process.env[locator];
  const mandate = { chain: "base", address: "0x0000000000000000000000000000000000000009", allowedContracts: ["0x0000000000000000000000000000000000000002"], maxAmountWei: "0", expiresAt: "2026-12-31T00:00:00Z" };
  const payload = { chain: "base", contract: "0x0000000000000000000000000000000000000002", valueWei: "0", transaction: {} };
  const result = await signWithWallet({
    chain: "base", mandate, payload, custody: { kind: "env-on-host", locator, derivationPath: "m/44'/60'/0'/0/0" }, now: "2026-09-05T00:00:00Z",
  });
  assert.equal(result.signed, false);
  assert.match(result.reason, /is not set/u);
});

test("signWithWallet refuses env-on-host custody whose derivationPath is missing for a mnemonic", async () => {
  const mnemonic = throwawayMnemonic();
  const locator = "KEY_MANAGEMENT_TEST_MNEMONIC_NO_PATH";
  process.env[locator] = mnemonic;
  try {
    const mandate = { chain: "base", address: "0x0000000000000000000000000000000000000009", allowedContracts: ["0x0000000000000000000000000000000000000002"], maxAmountWei: "0", expiresAt: "2026-12-31T00:00:00Z" };
    const payload = { chain: "base", contract: "0x0000000000000000000000000000000000000002", valueWei: "0", transaction: {} };
    const result = await signWithWallet({
      chain: "base", mandate, payload, custody: { kind: "env-on-host", locator, derivationPath: null }, now: "2026-09-05T00:00:00Z",
    });
    assert.equal(result.signed, false);
    assert.match(result.reason, /carries no derivationPath/u);
  } finally {
    delete process.env[locator];
  }
});
