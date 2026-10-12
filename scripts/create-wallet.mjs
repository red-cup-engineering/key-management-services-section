#!/usr/bin/env node
/**
 * Generates one new key with dual-copy custody, a `<id>.meta.json` sidecar (owner, role,
 * relations, createdAt -- never secrets), an appended WalletRegistry row, and a receipt. `id` is
 * only a filesystem slug; the registry row carries no id, only `{chain, address}` identity, per
 * the house ruling that a wallet is its address. Refuses rather than inventing `KEY_PASSPHRASE`
 * or `KEY_BACKUP_ROOT` when either is absent from the environment.
 */
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Wallet } from "ethers";
import { put } from "@red-cup-engineering/semiotic-eavt-services-section/store";
import { PrivateKey } from "@red-cup-engineering/hive-blockchain-client-service/keys.mjs";
import { keepCredential } from "@red-cup-engineering/credential-custody-service/keep";
import { backupKeyPath, configRoot, keyPath, metaPath } from "../src/keystore-paths.mjs";
import { hiveKeyPath, setHiveKey } from "../src/hive-keystore.mjs";
import { buildWalletRegistry, normalizeWalletRow } from "../src/wallet-registry.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(HERE, "..");
import { EVM_CHAINS as EVM_CHAIN_NAMES } from "../data/chains.mjs";
const EVM_CHAINS = new Set(EVM_CHAIN_NAMES);
const HIVE_CHAINS = new Set(["hive", "hive-engine"]);

function generateHivePrivateKey() {
  for (;;) {
    try {
      return new PrivateKey(randomBytes(32));
    } catch {
      // 32-byte scalar outside [1, n) is astronomically rare; retry with fresh randomness.
    }
  }
}

async function materializeEvmKey(passphrase) {
  const wallet = Wallet.createRandom();
  const fileContents = await wallet.encrypt(passphrase);
  return { address: wallet.address, fileContents };
}

function materializeHiveKey() {
  const privateKey = generateHivePrivateKey();
  return { address: privateKey.createPublic().toString(), wif: privateKey.toString() };
}

async function evmFileMatchesAddress(path, passphrase, expectedAddress) {
  const wallet = await Wallet.fromEncryptedJson(readFileSync(path, "utf8"), passphrase);
  return wallet.address.toLowerCase() === expectedAddress.toLowerCase();
}

function hiveFileMatchesAddress(path, expectedAddress) {
  return PrivateKey.from(readFileSync(path, "utf8").trim()).createPublic().toString() === expectedAddress;
}

function writePrivateFile(path, contents) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, contents, { encoding: "utf8", flag: "wx", mode: 0o600 });
}

function readRegistry(registryPath) {
  return registryPath && existsSync(registryPath) ? JSON.parse(readFileSync(registryPath, "utf8")) : null;
}

/**
 * @typedef {{id: string, chain: ("base"|"ethereum"|"arbitrum"|"avalanche"|"hive"|"hive-engine"), owner: string, role: string,
 *   relations?: readonly object[], passphrase: (string|undefined), backupRoot: (string|undefined),
 *   home?: string, registryPath?: string, journalRoot?: string}} CreateWalletInput
 */

/**
 * Creates one new key for `chain`, filed under the filesystem slug `id`, with dual-copy custody,
 * post-write verification, and a metadata sidecar. Never overwrites an existing key file for
 * the same id/chain, and refuses (via the registry's own duplicate check) if the freshly
 * generated address somehow already carries a row.
 * @param {CreateWalletInput} input
 * @returns {Promise<{created: false, reason: string}|{created: true, id: string, chain: string,
 *   address: string, custody: object, backup: object, metaPath: string, receipt: (string|null)}>}
 */
export async function createWallet({ id, chain, owner, role, relations = [], passphrase, backupRoot, home = process.env.HOME, credentialsDirectory = process.env.CREDENTIALS_DIRECTORY, registryPath, journalRoot = PACKAGE_ROOT, env = process.env }) {
  if (!passphrase) return { created: false, reason: "KEY_PASSPHRASE is not set in the environment" };
  if (!backupRoot) return { created: false, reason: "KEY_BACKUP_ROOT is not set in the environment" };
  if (!EVM_CHAINS.has(chain) && !HIVE_CHAINS.has(chain)) return { created: false, reason: `chain ${chain} is not supported` };

  const root = configRoot({ directory: credentialsDirectory });
  // A Hive key is an account's active role key, kept where the fleet signer reads it: the Hive
  // keystore (<root>/<account>/active.wif), under the home root and again under the backup root.
  const hive = HIVE_CHAINS.has(chain);
  const hiveRoots = hive ? { primary: resolve(root, "hive"), backup: resolve(backupRoot, "hive") } : null;
  const primaryPath = hive ? hiveKeyPath(id, "active", hiveRoots.primary) : keyPath({ configRoot: root, chain, id });
  const backupPath = hive ? hiveKeyPath(id, "active", hiveRoots.backup) : backupKeyPath({ backupRoot, chain, id });
  const sidecarPath = metaPath({ configRoot: root, chain, id });
  if (existsSync(primaryPath)) return { created: false, reason: `a key already exists at ${primaryPath}` };
  if (existsSync(backupPath)) return { created: false, reason: `a backup key already exists at ${backupPath}` };

  const materialized = EVM_CHAINS.has(chain) ? await materializeEvmKey(passphrase) : materializeHiveKey();
  if (hive) {
    await setHiveKey(id, "active", materialized.wif, { root: hiveRoots.primary, env });
    await setHiveKey(id, "active", materialized.wif, { root: hiveRoots.backup, env });
  } else {
    writePrivateFile(primaryPath, materialized.fileContents);
    writePrivateFile(backupPath, materialized.fileContents);
  }

  const verified = EVM_CHAINS.has(chain)
    ? (await evmFileMatchesAddress(primaryPath, passphrase, materialized.address)) && (await evmFileMatchesAddress(backupPath, passphrase, materialized.address))
    : hiveFileMatchesAddress(primaryPath, materialized.address) && hiveFileMatchesAddress(backupPath, materialized.address);
  if (!verified) return { created: false, reason: "primary and backup copies did not verify to the same address" };

  const createdAt = new Date().toISOString();
  mkdirSync(dirname(sidecarPath), { recursive: true, mode: 0o700 });
  writeFileSync(sidecarPath, `${JSON.stringify({ id, chain, owner, role, relations, createdAt }, null, 2)}\n`, "utf8");
  // The primary keystore and its sidecar are credentials of the host's store: kept there, so the copy written into
  // this process's (runtime) credentials directory outlives it. The backup copy stays under backupRoot.
  if (!hive && env.CREDENTIALS_STORE && env.CREDENTIALS_DIRECTORY && resolve(root) === resolve(env.CREDENTIALS_DIRECTORY)) {
    await keepCredential({ id: `wallet.${chain}.${id}`, service: "key-management", path: relative(root, primaryPath), value: materialized.fileContents, kind: "private-key", provider: chain }, env);
    await keepCredential({ id: `wallet.${chain}.${id}.meta`, service: "key-management", path: relative(root, sidecarPath), value: readFileSync(sidecarPath, "utf8"), kind: "other", provider: chain }, env);
  }

  // Hive has no address derivable from key material alone (an account name is a chain fact, not
  // a function of the key); the operator's own `id` names the intended account. EVM's derived
  // key IS the address. Either way the row's identity is {chain, address}, never a nickname.
  const registeredAddress = EVM_CHAINS.has(chain) ? materialized.address : id;
  const custody = { kind: "keystore-file", host: "bare-cedar-fog", locator: primaryPath, reference: EVM_CHAINS.has(chain) ? null : materialized.address };
  const backup = { kind: "keystore-file", host: "bare-cedar-fog", locator: backupPath, reference: EVM_CHAINS.has(chain) ? null : materialized.address };
  const row = normalizeWalletRow({
    chain, address: registeredAddress, owner, role, relations, custody, balanceReader: null, label: null,
    sources: [{ kind: "operator", locator: sidecarPath }], lastSeen: createdAt,
  });

  if (registryPath) {
    const existingRegistry = readRegistry(registryPath);
    let updatedRegistry;
    try {
      updatedRegistry = buildWalletRegistry({ derivedAt: createdAt, wallets: [...(existingRegistry?.wallets ?? []), row] });
    } catch (error) {
      return { created: false, reason: `address ${registeredAddress} is already registered: ${error.message}` };
    }
    writeFileSync(registryPath, `${JSON.stringify(updatedRegistry, null, 2)}\n`, "utf8");
  }

  const receipt = { id: put(journalRoot, "wallet-creation", { category: "wallet-creation", at: createdAt, id, chain, address: registeredAddress, owner, role, custody, backup }) };

  return { created: true, id, chain, address: registeredAddress, custody, backup, metaPath: sidecarPath, receipt: receipt?.id ?? null };
}

if (import.meta.main) {
  const { parseArgs } = await import("node:util");
  const { values } = parseArgs({
    options: {
      id: { type: "string" },
      chain: { type: "string" },
      owner: { type: "string" },
      role: { type: "string" },
      "registry-path": { type: "string" },
    },
  });
  const result = await createWallet({
    id: values.id,
    chain: values.chain,
    owner: values.owner,
    role: values.role,
    passphrase: process.env.KEY_PASSPHRASE,
    backupRoot: process.env.KEY_BACKUP_ROOT,
    registryPath: values["registry-path"],
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!result.created) process.exitCode = 1;
}
