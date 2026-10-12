#!/usr/bin/env node
/**
 * Signs one payload with one wallet's key, after checking it against a bounded mandate (the
 * same shape as Aagaard's per-account envelope check: chain, allowed contract/recipient set,
 * max amount, expiry). The caller never sees the private key -- only the signed bytes and a
 * receipt. A payload outside the mandate is refused as data, never signed.
 */
import { readFileSync } from "node:fs";
import { HDNodeWallet, Wallet } from "ethers";
import { put } from "@red-cup-engineering/semiotic-eavt-services-section/store";
import { PrivateKey } from "@red-cup-engineering/hive-blockchain-client-service/keys.mjs";
import { signTransaction as signHiveTransaction } from "@red-cup-engineering/hive-blockchain-client-service/transaction.mjs";
import { classifyEnvValue, cleanEnvValue, normalizeMnemonicPhrase } from "../src/derive-key-material.mjs";
import { checkMandateAllows } from "../src/mandate.mjs";
import { loadHiveKey } from "../src/hive-keystore.mjs";

import { EVM_CHAINS as EVM_CHAIN_NAMES, evmChainId } from "../data/chains.mjs";
const EVM_CHAINS = new Set(EVM_CHAIN_NAMES);

/**
 * Confirms `payload.tx`'s first operation is the transfer already mandate-checked: same
 * recipient, and its literal `amount` string matches `payload.amountText` verbatim -- so the
 * amount actually broadcast can never diverge from the integer `payload.amount` the mandate bounded.
 * @param {{tx: {operations: readonly [string, object][]}, recipient: string, amountText: string}} payload
 * @returns {boolean}
 */
function hiveTransactionMatchesPayload(payload) {
  const [operationName, operationBody] = payload.tx?.operations?.[0] ?? [];
  return operationName === "transfer" && operationBody?.to === payload.recipient && operationBody?.amount === payload.amountText;
}

/**
 * Derives an EVM signing wallet in memory from an `env-on-host` custody row: classifies
 * `custody.locator`'s value and derives it at `custody.derivationPath` (mnemonic, honoring the
 * `<locator>_PASSPHRASE` companion) or loads it directly (hex key). Never logged or returned.
 * @param {{kind: string, locator: string, derivationPath: (string|null)}} custody
 * @returns {import("ethers").Wallet|import("ethers").HDNodeWallet}
 * @throws {Error} When custody is unsupported, unset, unclassifiable, or missing derivationPath.
 */
function deriveEnvOnHostEvmWallet(custody) {
  if (!custody || custody.kind !== "env-on-host") {
    throw new Error(`sign-with-wallet: custody kind ${custody?.kind} cannot be derived in memory`);
  }
  const rawValue = process.env[custody.locator];
  if (!rawValue) throw new Error(`sign-with-wallet: environment variable ${custody.locator} is not set`);
  const classification = classifyEnvValue(rawValue);
  if (classification === "bip39-mnemonic") {
    if (!custody.derivationPath) throw new Error(`sign-with-wallet: env-on-host custody for ${custody.locator} carries no derivationPath`);
    const passphrase = process.env[`${custody.locator}_PASSPHRASE`];
    return HDNodeWallet.fromPhrase(normalizeMnemonicPhrase(rawValue), passphrase || undefined, custody.derivationPath);
  }
  if (classification === "evm-private-key") {
    const trimmed = cleanEnvValue(rawValue);
    return new Wallet(trimmed.startsWith("0x") ? trimmed : `0x${trimmed}`);
  }
  throw new Error(`sign-with-wallet: environment variable ${custody.locator} does not classify as a mnemonic or private key`);
}

/**
 * @typedef {{id?: string, chain: ("base"|"ethereum"|"arbitrum"|"avalanche"|"hive"|"hive-engine"), mandate: object,
 *   payload: object, keystorePath?: string, passphrase?: string,
 *   custody?: {kind: string, locator: string, derivationPath: (string|null)},
 *   now?: string, journalRoot?: string}} SignWithWalletInput
 */

/**
 * Checks `payload` against `mandate`, then signs with either a keystore file (`keystorePath` +
 * `passphrase`) or an `env-on-host` row's custody derived in memory (`custody`) -- exactly one
 * of the two. `id` defaults to `mandate.address` when omitted, since a registry row's identity
 * is `{chain, address}`, never a nickname. See `deriveEnvOnHostEvmWallet` for the custody path.
 * @param {SignWithWalletInput} input
 * @returns {Promise<{signed: false, reason: string}|{signed: true, id: string, chain: string, signature: (string|object), receipt: (string|null)}>}
 */
export async function signWithWallet({ id, chain, mandate, payload, keystorePath, passphrase, custody, hiveKeyRoot = process.env.HIVE_KEY_ROOT || undefined, now = new Date().toISOString(), journalRoot }) {
  try {
    checkMandateAllows({ mandate, payload, now });
    if (chain !== mandate.chain) throw new TypeError('signer chain differs from its mandate');
    if (EVM_CHAINS.has(chain)) {
      const tx = payload.transaction ?? {};
      const chainId = BigInt(evmChainId(chain));
      const supported = new Set(['to','from','value','chainId','nonce','data','gasLimit','gasPrice','maxFeePerGas','maxPriorityFeePerGas','type','accessList']);
      if (Object.keys(tx).some(key => !supported.has(key))) throw new TypeError('transaction contains an unmandated signing field');
      if (tx.to != null && String(tx.to).toLowerCase() !== payload.contract.toLowerCase()) throw new TypeError('transaction recipient differs from the checked contract');
      if (tx.value != null && BigInt(tx.value) !== BigInt(payload.valueWei)) throw new TypeError('transaction value differs from the checked amount');
      if (tx.chainId != null && BigInt(tx.chainId) !== chainId) throw new TypeError('transaction chain ID differs from the checked chain');
      if (tx.from != null && String(tx.from).toLowerCase() !== mandate.address.toLowerCase()) throw new TypeError('transaction sender differs from the mandate');
    }
  } catch (error) {
    return { signed: false, reason: error.message };
  }

  const walletId = id ?? mandate?.address ?? null;

  let signature;
  if (EVM_CHAINS.has(chain)) {
    let wallet;
    if (custody) {
      try {
        wallet = deriveEnvOnHostEvmWallet(custody);
      } catch (error) {
        return { signed: false, reason: error.message };
      }
    } else {
      if (!passphrase) return { signed: false, reason: "KEY_PASSPHRASE is not set in the environment" };
      wallet = await Wallet.fromEncryptedJson(readFileSync(keystorePath, "utf8"), passphrase);
    }
    if (wallet.address.toLowerCase() !== mandate.address.toLowerCase()) return { signed: false, reason: 'custodied wallet differs from the mandate address' };
    const transaction = { ...payload.transaction, to: payload.contract, value: BigInt(payload.valueWei), chainId: evmChainId(chain) };
    signature = await wallet.signTransaction(transaction);
  } else {
    if (!hiveTransactionMatchesPayload(payload)) return { signed: false, reason: "payload.tx transfer operation does not match payload.recipient" };
    // A Hive-Engine token transfer rides the same active-authority L1 transaction as a native one.
    let wif;
    try { wif = loadHiveKey(mandate.address, "active", { root: hiveKeyRoot, passphrase }); } catch (error) { return { signed: false, reason: error.message }; }
    if (!wif) return { signed: false, reason: `no active key is stored for @${mandate.address}` };
    signature = signHiveTransaction(payload.tx, PrivateKey.from(wif));
  }

  const recordedAt = now;
  let receiptId = null;
  if (journalRoot) {
    receiptId = put(journalRoot, "wallet-signature", { category: "sign-with-wallet", at: recordedAt, id: walletId, chain, mandateAddress: mandate.address, mandateExpiresAt: mandate.expiresAt });
  }

  return { signed: true, id: walletId, chain, signature, receipt: receiptId };
}

if (import.meta.main) {
  const { parseArgs } = await import("node:util");
  const { values } = parseArgs({
    options: {
      id: { type: "string" },
      chain: { type: "string" },
      mandate: { type: "string" },
      payload: { type: "string" },
      keystore: { type: "string" },
      "journal-root": { type: "string" },
    },
  });
  const result = await signWithWallet({
    id: values.id,
    chain: values.chain,
    mandate: JSON.parse(readFileSync(values.mandate, "utf8")),
    payload: JSON.parse(readFileSync(values.payload, "utf8")),
    keystorePath: values.keystore,
    passphrase: process.env.KEY_PASSPHRASE,
    journalRoot: values["journal-root"],
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!result.signed) process.exitCode = 1;
}
