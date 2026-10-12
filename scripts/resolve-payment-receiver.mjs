#!/usr/bin/env node
import { EVM_CHAINS } from "../data/chains.mjs";
/**
 * Resolves a payment rail's receiver address from the wallet registry, refusing mechanically
 * rather than returning an address the Group holds no verified custody for (2026-09-05 ruling,
 * payment-receivers-are-parameters-never-literals). The exported operation is pure -- given a
 * `walletId`, a `rail`, an already-derived `WalletRegistry`, and an already-computed
 * `CustodyVerification`, it decides; loading the registry file and running live custody
 * verification (`verifyWalletCustody`) are this file's `import.meta.main` block, mirroring
 * `verify-set-of-wallet-custody.mjs`'s own CLI wiring so custody is checked the same way
 * everywhere.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import {
  verifyEnvOnHost, verifyLocalEnvVariable, verifyLocalKeystoreFile, verifyRemoteKeystoreFileExistence, verifyWalletCustody,
} from "./verify-set-of-wallet-custody.mjs";
import { findEnvFilesToScan, findRepoRoot, readEnvVariablesFromFiles } from "./derive-set-of-wallets.mjs";
import { configRoot } from "../src/keystore-paths.mjs";

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_REGISTRY_PATH = resolve(PACKAGE_ROOT, "data", "records", "wallet-registry-records", "2026-09-05-wallet-registry.json");
const RAIL_CHAINS = Object.freeze({ hive: "hive", "base-usdc": "base" });

function parseWalletId(walletId) {
  const separatorIndex = typeof walletId === "string" ? walletId.indexOf(":") : -1;
  if (separatorIndex <= 0) return null;
  return { chain: walletId.slice(0, separatorIndex), address: walletId.slice(separatorIndex + 1) };
}

function addressesMatch(chain, left, right) {
  return EVM_CHAINS.includes(chain) ? left.toLowerCase() === right.toLowerCase() : left === right;
}

function findRegistryRow(registry, chain, address) {
  return (registry?.wallets ?? []).find((wallet) => wallet.chain === chain && addressesMatch(chain, wallet.address, address));
}

function findAgreedCustodyRow(custodyVerification, chain, address) {
  return (custodyVerification?.rows ?? []).find((row) => row.chain === chain && addressesMatch(chain, row.address, address) && row.status === "agreed");
}

function describeCustodyStatus(custodyVerification, chain, address) {
  const rows = (custodyVerification?.rows ?? []).filter((row) => row.chain === chain && addressesMatch(chain, row.address, address));
  return rows.length === 0 ? "no custody rows found" : rows.map((row) => `${row.custodyKind}:${row.status}`).join(", ");
}

/**
 * Resolves a payment rail's receiver address from the wallet registry, refusing mechanically
 * rather than returning an address the Group holds no verified custody for.
 * @param {{walletId: string, rail: string, registry: {wallets: readonly object[]},
 *   custodyVerification: {rows: readonly object[]}}} input
 * @returns {({walletId: string, rail: string, address: string}|
 *   {refused: "RECEIVER_NOT_IN_CUSTODY", walletId: string, rail: string, reason: string})}
 */
export function resolvePaymentReceiver({ walletId, rail, registry, custodyVerification }) {
  const refuse = (reason) => ({ refused: "RECEIVER_NOT_IN_CUSTODY", walletId, rail, reason });
  const expectedChain = RAIL_CHAINS[rail];
  if (!expectedChain) return refuse(`rail "${rail}" has no chain-wallet backing in the registry`);
  const parsed = parseWalletId(walletId);
  if (!parsed) return refuse(`walletId "${walletId}" is not a "<chain>:<address>" identity`);
  if (parsed.chain !== expectedChain) return refuse(`walletId chain "${parsed.chain}" does not match rail "${rail}"'s expected chain "${expectedChain}"`);
  const row = findRegistryRow(registry, parsed.chain, parsed.address);
  if (!row) return refuse(`wallet "${walletId}" is not a registered wallet`);
  const agreed = findAgreedCustodyRow(custodyVerification, row.chain, row.address);
  if (!agreed) return refuse(`wallet "${walletId}" has no custody entry verified as "agreed" (${describeCustodyStatus(custodyVerification, row.chain, row.address)})`);
  return { walletId, rail, address: row.address };
}

if (import.meta.main) {
  const { values } = parseArgs({
    options: {
      walletId: { type: "string" },
      rail: { type: "string" },
      registry: { type: "string" },
      "checkout-root": { type: "string" },
    },
  });
  if (!values.walletId || !values.rail) {
    process.stderr.write("error: --walletId <chain:address> and --rail <rail> are required\n");
    process.exit(2);
  }
  const registry = JSON.parse(readFileSync(values.registry ?? DEFAULT_REGISTRY_PATH, "utf8"));
  const parsed = parseWalletId(values.walletId);
  const singleWalletRegistry = {
    ...registry,
    wallets: parsed ? registry.wallets.filter((wallet) => wallet.chain === parsed.chain && addressesMatch(parsed.chain, wallet.address, parsed.address)) : [],
  };
  const passphrase = process.env.KEY_PASSPHRASE;
  const backupRoot = process.env.KEY_BACKUP_ROOT;
  const checkoutRoot = values["checkout-root"] ?? findRepoRoot(PACKAGE_ROOT);
  const env = { ...readEnvVariablesFromFiles(findEnvFilesToScan({ checkoutRoot, houseConfigRoot: configRoot({ optional: true }) })), ...process.env };
  const custodyVerification = await verifyWalletCustody({
    registry: singleWalletRegistry,
    checkLocalKeystore: (wallet) => verifyLocalKeystoreFile(wallet, { passphrase, backupRoot }),
    checkRemoteKeystore: (wallet) => verifyRemoteKeystoreFileExistence(wallet),
    checkEnvOnHost: (wallet) => verifyEnvOnHost(wallet),
    checkLocalEnv: (wallet) => verifyLocalEnvVariable(wallet, { env }),
  });
  const result = resolvePaymentReceiver({ walletId: values.walletId, rail: values.rail, registry, custodyVerification });
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (result.refused) process.exitCode = 1;
}
