#!/usr/bin/env node
/**
 * Derives the WalletRegistry: never hand-written. Folds four live sources -- this host's own
 * runtime environment (every `.env`/`.env.*` beside the checkout root, plus every `*.env` under
 * this process's credentials directory), its keystore directory, the ethereum-services-section census, and tree
 * relations -- plus a house-carrier fold for wallets no live source names. Never guesses custody
 * or owner.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { hostname } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { getAddress } from "ethers";
import { buildWalletRegistry, mergeWalletObservations, normalizeWalletRow } from "../src/wallet-registry.mjs";
import {
  classifyEnvValue, deriveEvmAddressesFromMnemonic, deriveEvmAddressFromKeystoreJson,
  deriveEvmAddressFromPrivateKey, deriveHivePublicKeyFromWif,
} from "../src/derive-key-material.mjs";
import { parseEnvFileText } from "../src/env-file.mjs";
import { configRoot } from "../src/keystore-paths.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(HERE, "..");
const DEFAULT_FACTS_PATH = join(PACKAGE_ROOT, "data", "records", "wallet-facts-source-records", "2026-09-05-wallet-facts-source.json");
const HIVE_BALANCE_READER = "@red-cup-engineering/hive-blockchain-client-service";
const BASE_BALANCE_READER = "@red-cup-engineering/treasury-observation-service/native";
import { WALLET_CHAINS as KEYSTORE_CHAINS, EVM_CHAINS } from "../data/chains.mjs";
const EXTENSION_BY_CHAIN = { ...Object.fromEntries(EVM_CHAINS.map((chain) => [chain, "json"])), hive: "wif", "hive-engine": "wif" };
const HIVE_ADDRESS_PATTERN = /^[a-z][a-z0-9.-]{2,15}$/u;
const TREE_GREP_EXCLUDES = ["--exclude-dir=node_modules", "--exclude-dir=legacy", "--exclude-dir=.venv", "--exclude-dir=.git", "--exclude-dir=dist", "--exclude-dir=build", "--exclude-dir=coverage", "--exclude-dir=.tmp"];

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

/**
 * Resolves the enclosing Git worktree. Falls back to `startDir` when it is not
 * inside one, so a checkout-independent run degrades to a narrower search.
 * @param {string} startDir
 * @returns {string}
 */
export function findRepoRoot(startDir) {
  try {
    return execFileSync("git", ["-C", resolve(startDir), "rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();
  } catch {
    return startDir;
  }
}

/**
 * Locates the ethereum-services-section census script relative to one of that package's own
 * published exports (it carries no `./scripts/*` export; a real exported src module is the
 * anchor -- its package root is two directories up). See the missing-capability friction
 * admitted against that package's export map for the durable fix.
 * @param {(id: string) => string} resolveModule A `createRequire(...).resolve` bound to the caller.
 * @returns {string} Absolute path to `census-enterprise-wallets.mjs`.
 */
export function resolveEthereumCensusScript(resolveModule) {
  const anchorModulePath = resolveModule("@red-cup-engineering/ethereum-engineering-services-section/settlement-key-custody");
  const packageRoot = dirname(dirname(anchorModulePath));
  return join(packageRoot, "scripts", "census-enterprise-wallets.mjs");
}

/**
 * Reads every chain-binding JSON file under one settlement's `content/evm/accounts/`
 * directory. Returns an empty list for a settlement whose binding directory is absent.
 * @param {string} directory
 * @returns {readonly object[]}
 */
export function readBindingFilesFromDirectory(directory) {
  let names;
  try {
    names = readdirSync(directory);
  } catch {
    return [];
  }
  return names.filter((name) => name.endsWith(".json")).map((name) => JSON.parse(readFileSync(join(directory, name), "utf8")));
}

/**
 * A settlement root's final path segment, lowercased/kebabbed -- kept as a readable `sources[]`
 * locator even though it no longer disambiguates a row id (identity is `{chain, address}` now).
 * @param {string} root
 * @returns {string}
 */
export function slugFromSettlementRoot(root) {
  const segment = root.split("/").filter(Boolean).at(-1) ?? "settlement";
  return segment.toLowerCase().replace(/[^a-z0-9]+/gu, "-").replace(/^-+|-+$/gu, "") || "settlement";
}

/**
 * (Source c, "as today") Builds one enterprise-account WalletRegistry row from one bound census
 * settlement's chain binding. Only the settlement's own recorded fields are used.
 * @param {{nodeId: string, root: string}} settlement
 * @param {{chain: {chainId: number}, account: {address: string}, policy: {custody: string, signer: string, keyVersion?: string}}} binding
 * @param {string} derivedAt
 * @returns {object}
 */
export function enterpriseRowFromBinding(settlement, binding, derivedAt) {
  const custody = binding.policy?.custody === "remote-cloud-kms-hsm"
    ? { kind: "kms", host: "gcp-cloud-kms", locator: binding.policy.keyVersion, reference: null }
    : { kind: "unknown", host: null, locator: null, reference: null };
  return {
    chain: "ethereum",
    address: getAddress(binding.account.address),
    owner: `enterprise:${settlement.nodeId}`,
    role: "enterprise-account",
    relations: [{ kind: "signs-for", target: binding.policy.signer }],
    custody,
    balanceReader: BASE_BALANCE_READER,
    label: null,
    sources: [{ kind: "ethereum-census", locator: settlement.root }],
    lastSeen: derivedAt,
  };
}

/**
 * (Source a) Scans a name-to-value env map for private-key- and public-identifier-shaped
 * values, deriving public addresses and never returning a value itself. A Hive WIF needs a
 * chain lookup to resolve its owning account name; a key `resolveHiveAccount` cannot resolve
 * contributes no row (never a fabricated address) and is named under `unresolved` instead. A
 * checksummed BIP-39 mnemonic derives ten EVM addresses (`m/44'/60'/0'/0/{0..9}`), honoring a
 * companion `<name>_PASSPHRASE` variable when present; Hive derivation from a mnemonic is not
 * attempted (the tree's Hive client has no mnemonic support -- see the missing-capability
 * friction filed against it).
 * @param {{variables: Readonly<Record<string,string>>, host: string, derivedAt: string,
 *   resolveHiveAccount: (publicKey: string) => Promise<(string|null)>}} input
 * @returns {Promise<{rows: readonly object[], unresolved: readonly {locator: string, publicKey: string}[]}>}
 */
export async function scanEnvironmentForWalletFacts({ variables, host, derivedAt, resolveHiveAccount }) {
  const rows = [];
  const unresolved = [];
  for (const [name, value] of Object.entries(variables)) {
    const kind = classifyEnvValue(value);
    if (kind === "evm-private-key") {
      let address;
      try { address = deriveEvmAddressFromPrivateKey(value); } catch { continue; }
      rows.push({
        chain: "base", address, owner: "org", role: "auxiliary", relations: [],
        custody: { kind: "env-on-host", host, locator: name, reference: null },
        balanceReader: BASE_BALANCE_READER, label: null,
        sources: [{ kind: "env-private-key", locator: name }], lastSeen: derivedAt,
      });
    } else if (kind === "hive-wif") {
      let publicKey;
      try { publicKey = deriveHivePublicKeyFromWif(value); } catch { continue; }
      const account = await resolveHiveAccount(publicKey);
      if (!account) { unresolved.push({ locator: name, publicKey }); continue; }
      rows.push({
        chain: "hive", address: account, owner: "org", role: "auxiliary", relations: [],
        custody: { kind: "env-on-host", host, locator: name, reference: publicKey },
        balanceReader: HIVE_BALANCE_READER, label: null,
        sources: [{ kind: "env-private-key", locator: name }], lastSeen: derivedAt,
      });
    } else if (kind === "evm-address") {
      rows.push({
        chain: "base", address: getAddress(value.trim()), owner: "org", role: "auxiliary", relations: [],
        custody: { kind: "unknown", host: null, locator: null, reference: name },
        balanceReader: BASE_BALANCE_READER, label: null,
        sources: [{ kind: "env-public-identifier", locator: name }], lastSeen: derivedAt,
      });
    } else if (kind === "hive-account" && /account|hive/iu.test(name)) {
      // a bare lowercase word matches the account-name shape as readily as a username or a flag
      // value (e.g. "emsenn", "hello"); requiring the variable's own name to hint at an account
      // is the only bound available short of a live chain lookup for every such value.
      rows.push({
        chain: "hive", address: value.trim(), owner: "org", role: "auxiliary", relations: [],
        custody: { kind: "unknown", host: null, locator: null, reference: name },
        balanceReader: HIVE_BALANCE_READER, label: null,
        sources: [{ kind: "env-public-identifier", locator: name }], lastSeen: derivedAt,
      });
    } else if (kind === "evm-keystore-json") {
      let address;
      try { address = deriveEvmAddressFromKeystoreJson(value); } catch { continue; }
      rows.push({
        chain: "base", address, owner: "org", role: "auxiliary", relations: [],
        custody: { kind: "env-on-host", host, locator: name, reference: null },
        balanceReader: BASE_BALANCE_READER, label: null,
        sources: [{ kind: "env-private-key", locator: name }], lastSeen: derivedAt,
      });
    } else if (kind === "bip39-mnemonic") {
      // an EVM address a mnemonic derives is identical on every EVM chain; it is registered under
      // "base" only (this section's existing convention for every other EVM-key-shaped env row),
      // never as a second row under "ethereum".
      let derived;
      try { derived = deriveEvmAddressesFromMnemonic(value, { passphrase: variables[`${name}_PASSPHRASE`] }); } catch { continue; }
      for (const { derivationPath, address } of derived) {
        rows.push({
          chain: "base", address, owner: "org", role: "auxiliary", relations: [],
          custody: { kind: "env-on-host", host, locator: name, reference: null, derivationPath },
          balanceReader: BASE_BALANCE_READER, label: null,
          sources: [{ kind: "env-private-key", locator: name }], lastSeen: derivedAt,
        });
      }
    }
  }
  return { rows, unresolved };
}

function safeReaddir(directory) {
  try { return readdirSync(directory); } catch { return []; }
}

/**
 * Lists every environment file this host's runtime loader would read: `.env` and every
 * `.env.*` sibling directly under `checkoutRoot`, plus every `*.env` file directly under
 * `houseConfigRoot` (this process's credentials directory, rendered by credential custody).
 * Sorted for stable output; a missing directory or file is simply absent, never an error.
 * @param {{checkoutRoot: string, houseConfigRoot: (string|null)}} input
 * @returns {readonly string[]} Absolute paths, sorted.
 */
export function findEnvFilesToScan({ checkoutRoot, houseConfigRoot }) {
  const paths = [];
  const primaryEnvPath = join(checkoutRoot, ".env");
  if (existsSync(primaryEnvPath)) paths.push(primaryEnvPath);
  for (const name of safeReaddir(checkoutRoot)) {
    if (name.startsWith(".env.")) paths.push(join(checkoutRoot, name));
  }
  if (houseConfigRoot) {
    for (const name of safeReaddir(houseConfigRoot)) {
      if (name.endsWith(".env")) paths.push(join(houseConfigRoot, name));
    }
  }
  return paths.sort();
}

/**
 * Reads and merges every env file's variables (later files' values win on a name collision).
 * @param {readonly string[]} paths
 * @returns {Readonly<Record<string,string>>}
 */
export function readEnvVariablesFromFiles(paths) {
  let variables = {};
  for (const path of paths) variables = { ...variables, ...parseEnvFileText(readFileSync(path, "utf8")) };
  return Object.freeze(variables);
}

/**
 * (Source b) Scans `<configRoot>/keys/<chain>/*.<ext>` for keystore files, pairing each with its
 * `<id>.meta.json` sidecar when present (the owner/role/relations `create-wallet.mjs` wrote) and
 * a second custody entry when the same filename exists under `backupRoot`. An EVM address comes
 * from the keystore's own plaintext `address` field (never decrypted); a Hive address is the
 * filename itself, which this cannot independently confirm is chain-registered.
 * @param {{configRoot: string, backupRoot: (string|null), host: string, derivedAt: string}} input
 * @returns {readonly object[]}
 */
export function scanKeystoreDirectoriesForWalletFacts({ configRoot: root, backupRoot, host, derivedAt }) {
  const rows = [];
  for (const chain of KEYSTORE_CHAINS) {
    const directory = join(root, "keys", chain);
    const extension = EXTENSION_BY_CHAIN[chain];
    for (const filename of safeReaddir(directory)) {
      if (!filename.endsWith(`.${extension}`) || filename.endsWith(".meta.json")) continue;
      const primaryPath = join(directory, filename);
      const id = filename.slice(0, -(extension.length + 1));
      let address;
      if (extension === "json") {
        try {
          const parsed = JSON.parse(readFileSync(primaryPath, "utf8"));
          address = getAddress(`0x${String(parsed.address ?? "").replace(/^0x/u, "")}`);
        } catch { continue; }
      } else {
        if (!HIVE_ADDRESS_PATTERN.test(id)) continue;
        address = id;
      }
      const sidecarPath = join(directory, `${id}.meta.json`);
      const sidecar = existsSync(sidecarPath) ? JSON.parse(readFileSync(sidecarPath, "utf8")) : null;
      const custodies = [{ kind: "keystore-file", host, locator: primaryPath, reference: null }];
      const backupPath = backupRoot ? join(backupRoot, "keys", chain, filename) : null;
      if (backupPath && existsSync(backupPath)) custodies.push({ kind: "keystore-file", host, locator: backupPath, reference: null });
      rows.push({
        chain, address, owner: sidecar?.owner ?? "org", role: sidecar?.role ?? "auxiliary",
        relations: sidecar?.relations ?? [], custodies,
        balanceReader: chain === "hive" || chain === "hive-engine" ? HIVE_BALANCE_READER : BASE_BALANCE_READER,
        label: null, sources: [{ kind: "keystore-file", locator: primaryPath }], lastSeen: derivedAt,
      });
    }
  }
  return rows;
}

/**
 * (Source d) Finds every package under the checkout whose `.mjs`/`.mts` source reads
 * `process.env.<name>`, by name (excludes `node_modules`, `lib/legacy`). A grep miss is a
 * negative finding, never an error.
 * @param {{name: string, checkoutRoot: string}} input
 * @returns {readonly string[]} Package names (nearest ancestor `package.json`), deduped and sorted.
 */
export function findEnvVariableConsumers({ name, checkoutRoot }) {
  let matches;
  try {
    matches = execFileSync("grep", ["-rlE", `process\\.env\\.${escapeRegExp(name)}\\b`, "--include=*.mjs", "--include=*.mts", "-I", ...TREE_GREP_EXCLUDES, checkoutRoot], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
  } catch (error) {
    if (error.status === 1) return [];
    throw error;
  }
  const packageNames = new Set();
  for (const filePath of matches.split("\n").filter(Boolean)) {
    const packageName = nearestPackageName(filePath);
    if (packageName) packageNames.add(packageName);
  }
  return [...packageNames].sort();
}

function nearestPackageName(filePath) {
  let dir = dirname(filePath);
  for (let depth = 0; depth < 14; depth += 1) {
    const candidate = join(dir, "package.json");
    if (existsSync(candidate)) {
      try { return JSON.parse(readFileSync(candidate, "utf8")).name ?? null; } catch { return null; }
    }
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
  return null;
}

/**
 * (Source d) Finds an owning binding for each address in one batched tree walk: an enterprise
 * `package.json` naming the address literally, or a `lib/agency/characters/...` entry naming
 * it. An address with no such binding is simply absent from the returned map -- the caller
 * applies the `"org"` default itself, never guessing a binding that isn't there.
 * @param {{addresses: readonly string[], checkoutRoot: string}} input
 * @returns {Readonly<Record<string, {kind: ("enterprise"|"character"), value: string}>>}
 */
export function findOwnerBindingsForAddresses({ addresses, checkoutRoot }) {
  if (addresses.length === 0) return {};
  const pattern = addresses.map(escapeRegExp).join("|");
  let matches;
  try {
    matches = execFileSync("grep", ["-rlE", pattern, "-I", "--include=*.json", "--include=*.md", "--include=*.mjs", "--include=*.mts", ...TREE_GREP_EXCLUDES, checkoutRoot], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
  } catch (error) {
    if (error.status !== 1) throw error;
    matches = "";
  }
  const bindings = {};
  for (const filePath of matches.split("\n").filter(Boolean)) {
    if (filePath.includes("key-management-services-section/data/")) continue; // this package's own derived carriers are never a binding
    const content = readFileSync(filePath, "utf8");
    for (const address of addresses) {
      if (bindings[address] || !content.includes(address)) continue;
      const characterMatch = /(.*\/agency\/characters\/[^/]+)/u.exec(filePath);
      if (characterMatch) { bindings[address] = { kind: "character", value: relative(checkoutRoot, characterMatch[1]) }; continue; }
      if (basename(filePath) === "package.json") {
        try {
          const name = JSON.parse(content).name;
          if (name) bindings[address] = { kind: "enterprise", value: name };
        } catch { /* invalid package.json -- not usable as a binding source */ }
      }
    }
  }
  return bindings;
}

/**
 * Applies source-d enrichment (tree relations, owner bindings) to a set of already-normalized
 * proto-rows in place of guessing: adds a `consumed-by` relation per env-locator consumer found,
 * and replaces the generic `"org"` owner with an `enterprise:`/`character:` binding when the
 * address is literally named in the tree.
 * @param {{rows: readonly object[], checkoutRoot: string}} input
 * @returns {readonly object[]}
 */
export function enrichRowsWithTreeRelations({ rows, checkoutRoot }) {
  const addresses = [...new Set(rows.filter((row) => row.owner === "org").map((row) => row.address))];
  const bindings = findOwnerBindingsForAddresses({ addresses, checkoutRoot });
  return rows.map((row) => {
    const locatorNames = new Set();
    for (const custody of row.custodies) {
      if (custody.kind === "env-on-host") locatorNames.add(custody.locator);
      else if (custody.kind === "unknown" && custody.reference) locatorNames.add(custody.reference);
    }
    const relations = [...row.relations];
    for (const locatorName of locatorNames) {
      for (const packageName of findEnvVariableConsumers({ name: locatorName, checkoutRoot })) {
        if (!relations.some((relation) => relation.kind === "consumed-by" && relation.target === packageName)) {
          relations.push({ kind: "consumed-by", target: packageName });
        }
      }
    }
    const binding = bindings[row.address];
    const owner = row.owner === "org" && binding ? `${binding.kind}:${binding.value}` : row.owner;
    const sources = binding ? [...row.sources, { kind: "tree-relation", locator: binding.value }] : row.sources;
    return { ...row, owner, relations, sources };
  });
}

/**
 * Folds the house-carrier facts file (Hive accounts and Base wallets named in house notes, each
 * citing its own source carrier -- never a nickname) into proto-rows. Addresses are checksummed;
 * ids are never read from this file into a row.
 * @param {{hiveAccounts: readonly object[], baseWallets: readonly object[], derivedAt: string}} input
 * @returns {readonly object[]}
 */
export function carrierRowsFromFacts({ hiveAccounts, baseWallets, derivedAt }) {
  const hiveRows = hiveAccounts.map((fact) => ({
    chain: "hive", address: fact.account, owner: fact.owner, role: fact.role, relations: [],
    custody: fact.custody, balanceReader: HIVE_BALANCE_READER, label: null,
    sources: [{ kind: "carrier", locator: fact.source }], lastSeen: derivedAt,
  }));
  const baseRows = baseWallets.map((fact) => ({
    chain: "base", address: getAddress(fact.address), owner: fact.owner, role: fact.role, relations: [],
    custody: { kind: "unknown", host: null, locator: null, reference: null }, balanceReader: BASE_BALANCE_READER, label: null,
    sources: [{ kind: "carrier", locator: fact.source }], lastSeen: derivedAt,
  }));
  return [...hiveRows, ...baseRows];
}

/**
 * Derives the full WalletRegistry: folds the census, the runtime environment, the keystore
 * directory, tree-relation enrichment, and the house-carrier facts, then merges same-identity
 * observations into one row each. Pure with respect to its inputs -- every side effect (the
 * census subprocess, env/keystore/tree reads) happens in the caller-supplied functions.
 * @param {{derivedAt: string, host: string, census: {settlements: readonly {nodeId: string, root: string, status: string}[]},
 *   envVariables: Readonly<Record<string,string>>, resolveHiveAccount: Function,
 *   keystoreConfigRoot: string, keystoreBackupRoot: (string|null), checkoutRoot: string,
 *   carrierFacts: {hiveAccounts: readonly object[], baseWallets: readonly object[]},
 *   readBindingFiles: (settlementRoot: string) => readonly object[]}} input
 * @returns {Promise<{registry: import("../src/wallet-registry.mjs").WalletRegistry,
 *   unresolvedHiveKeys: readonly {locator: string, publicKey: string}[]}>}
 */
export async function deriveWalletRegistry({ derivedAt, host, census, envVariables, resolveHiveAccount, keystoreConfigRoot, keystoreBackupRoot, checkoutRoot, carrierFacts, readBindingFiles }) {
  const enterpriseRows = [];
  for (const settlement of census.settlements ?? []) {
    if (settlement.status !== "bound") continue;
    for (const binding of readBindingFiles(settlement.root)) enterpriseRows.push(enterpriseRowFromBinding(settlement, binding, derivedAt));
  }
  const { rows: envRows, unresolved: unresolvedHiveKeys } = await scanEnvironmentForWalletFacts({ variables: envVariables, host, derivedAt, resolveHiveAccount });
  const keystoreRows = scanKeystoreDirectoriesForWalletFacts({ configRoot: keystoreConfigRoot, backupRoot: keystoreBackupRoot, host, derivedAt });
  const carrierRows = carrierRowsFromFacts({ ...carrierFacts, derivedAt });
  const normalized = [...enterpriseRows, ...envRows, ...keystoreRows, ...carrierRows].map(normalizeWalletRow);
  const enriched = checkoutRoot ? enrichRowsWithTreeRelations({ rows: normalized, checkoutRoot }) : normalized;
  const registry = buildWalletRegistry({ derivedAt, wallets: mergeWalletObservations(enriched.map(normalizeWalletRow)) });
  return { registry, unresolvedHiveKeys };
}

/**
 * Merges a second host's own already-derived WalletRegistry readout into this one (point 3 of
 * the key-custody repair: a wallet known on two hosts carries two custody entries).
 * @param {{primary: import("../src/wallet-registry.mjs").WalletRegistry, secondary: object, derivedAt: string}} input
 * @returns {import("../src/wallet-registry.mjs").WalletRegistry}
 */
export function mergeHostReadouts({ primary, secondary, derivedAt }) {
  return buildWalletRegistry({ derivedAt, wallets: mergeWalletObservations([...primary.wallets, ...secondary.wallets].map(normalizeWalletRow)) });
}

/**
 * Resolves the Hive account owning a public key via a live, keyless
 * `condenser_api.get_key_references` read -- the only way to learn a Hive WIF's account name,
 * since Hive account names are not derivable from key material alone. Returns `null` (never a
 * guess) on no match or a transport failure.
 * @param {string} publicKey
 * @returns {Promise<(string|null)>}
 */
export async function resolveHiveAccountViaChain(publicKey) {
  const { RpcClient } = await import("@red-cup-engineering/hive-blockchain-client-service/src/rpc.mjs");
  try {
    const result = await new RpcClient().call("condenser_api.get_key_references", [[publicKey]]);
    return result?.[0]?.[0] ?? null;
  } catch {
    return null;
  }
}

if (import.meta.main) {
  const { values } = parseArgs({
    options: {
      workspace: { type: "string" },
      facts: { type: "string" },
      out: { type: "string" },
      host: { type: "string" },
      "checkout-root": { type: "string" },
      "merge-with": { type: "string" },
    },
  });
  const require = createRequire(import.meta.url);
  const censusScript = resolveEthereumCensusScript(require.resolve.bind(require));
  const censusArgs = values.workspace ? [censusScript, "--workspace", values.workspace] : [censusScript];
  const census = JSON.parse(execFileSync(process.execPath, censusArgs, { encoding: "utf8" }));
  const facts = JSON.parse(readFileSync(values.facts ?? DEFAULT_FACTS_PATH, "utf8"));
  const host = values.host ?? hostname();
  const checkoutRoot = values["checkout-root"] ?? findRepoRoot(PACKAGE_ROOT);
  const houseConfigRoot = configRoot();
  const envFilePaths = findEnvFilesToScan({ checkoutRoot, houseConfigRoot });
  const derivedAt = new Date().toISOString();
  let { registry, unresolvedHiveKeys } = await deriveWalletRegistry({
    derivedAt, host, census,
    envVariables: readEnvVariablesFromFiles(envFilePaths),
    resolveHiveAccount: resolveHiveAccountViaChain,
    keystoreConfigRoot: houseConfigRoot,
    keystoreBackupRoot: process.env.KEY_BACKUP_ROOT ?? null,
    checkoutRoot,
    carrierFacts: { hiveAccounts: facts.hiveAccounts, baseWallets: facts.baseWallets },
    readBindingFiles: (settlementRoot) => readBindingFilesFromDirectory(join(census.workspace, settlementRoot, "content", "evm", "accounts")),
  });
  if (values["merge-with"]) {
    const secondary = JSON.parse(readFileSync(values["merge-with"], "utf8"));
    registry = mergeHostReadouts({ primary: registry, secondary, derivedAt });
  }
  if (unresolvedHiveKeys.length > 0) {
    process.stderr.write(`${JSON.stringify({ warning: "unresolved-hive-keys-never-guessed", entries: unresolvedHiveKeys })}\n`);
  }
  const outPath = values.out ?? join(PACKAGE_ROOT, "data", "records", "wallet-registry-records", "2026-09-05-wallet-registry.json");
  writeFileSync(outPath, `${JSON.stringify(registry, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ path: outPath, walletCount: registry.wallets.length, scannedEnvFiles: envFilePaths })}\n`);
}
