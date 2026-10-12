import { WALLET_CHAINS as SUPPORTED_CHAINS } from "../data/chains.mjs";
const CHAINS = new Set(SUPPORTED_CHAINS);
import { EVM_CHAINS as EVM_CHAIN_NAMES } from "../data/chains.mjs";
const EVM_CHAINS = new Set(EVM_CHAIN_NAMES);
const ROLES = new Set(["treasury", "signer", "policy-signer", "enterprise-account", "auxiliary", "pool", "game"]);
const RELATION_KINDS = new Set(["funds", "signs-for", "controlled-by", "consumed-by"]);
const CUSTODY_KINDS = new Set(["env-on-host", "keystore-file", "kms", "hardware", "founder-wallet-app", "unknown"]);
const SOURCE_KINDS = new Set(["env-private-key", "env-public-identifier", "keystore-file", "ethereum-census", "tree-relation", "carrier", "operator"]);
const OWNER_PATTERN = /^(org|founder|enterprise:[A-Za-z0-9][A-Za-z0-9._-]*|character:[A-Za-z0-9][A-Za-z0-9._/-]*)$/u;
const EVM_ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/u;
const HIVE_ADDRESS_PATTERN = /^[a-z][a-z0-9.-]{2,15}$/u;

/**
 * A wallet's identity is `{chain, address}` -- never a nickname.
 * @param {string} chain
 * @param {string} address
 * @returns {string} The address, lowercased for EVM chains (comparison/sort key only -- the
 *   stored `address` field keeps whatever casing the caller gave, normally checksummed).
 */
function addressKey(chain, address) {
  return EVM_CHAINS.has(chain) ? address.toLowerCase() : address;
}

/** @typedef {{kind: ("funds"|"signs-for"|"controlled-by"|"consumed-by"), target: string}} WalletRelation */
/**
 * @typedef {{kind: ("env-on-host"|"keystore-file"|"kms"|"hardware"|"founder-wallet-app"|"unknown"),
 *   host: (string|null), locator: (string|null), reference: (string|null),
 *   derivationPath: (string|null)}} WalletCustody
 */
/**
 * @typedef {{kind: ("env-private-key"|"env-public-identifier"|"keystore-file"|"ethereum-census"|
 *   "tree-relation"|"carrier"|"operator"), locator: string}} WalletSource
 */
/** @typedef {{text: string, source: string}} WalletLabel */
/**
 * @typedef {{chain: ("base"|"ethereum"|"arbitrum"|"avalanche"|"hive"|"hive-engine"), address: string,
 *   owner: string, role: string, relations: readonly WalletRelation[],
 *   custody: WalletCustody, custodies: readonly WalletCustody[],
 *   balanceReader: (string|null), label: (WalletLabel|null), sources: readonly WalletSource[],
 *   lastSeen: string}} WalletRow
 */
/** @typedef {{type: "WalletRegistry", version: 1, derivedAt: string, wallets: readonly WalletRow[]}} WalletRegistry */

function requireString(value, label) {
  if (typeof value !== "string" || value.length === 0) throw new TypeError(`wallet-registry: ${label} must be a nonempty string`);
  return value;
}

/**
 * Validates and freezes one custody descriptor. `kind: "unknown"` is the only kind that may
 * carry null host/locator (it may still carry a public `reference`, e.g. an env variable name
 * whose value is a bare address); every other kind must name both host and locator.
 * `derivationPath` is set only for a mnemonic-derived `env-on-host` entry (e.g.
 * `m/44'/60'/0'/0/3`) -- absent from every other custody, never invented.
 * @param {object} custody
 * @returns {WalletCustody}
 * @throws {TypeError} When the custody kind is unsupported or a non-unknown kind is missing host/locator.
 */
export function normalizeWalletCustody(custody) {
  if (!custody || typeof custody !== "object") throw new TypeError("wallet-registry: custody must be an object");
  if (!CUSTODY_KINDS.has(custody.kind)) throw new TypeError(`wallet-registry: custody.kind ${custody.kind} is not supported`);
  const reference = custody.reference ?? null;
  if (reference !== null && typeof reference !== "string") throw new TypeError("wallet-registry: custody.reference must be a string or null");
  const derivationPath = custody.derivationPath ?? null;
  if (derivationPath !== null && typeof derivationPath !== "string") throw new TypeError("wallet-registry: custody.derivationPath must be a string or null");
  if (custody.kind === "unknown") {
    if (custody.host !== null && custody.host !== undefined) throw new TypeError("wallet-registry: unknown custody must not name a host");
    if (custody.locator !== null && custody.locator !== undefined) throw new TypeError("wallet-registry: unknown custody must not name a locator");
    return Object.freeze({ kind: "unknown", host: null, locator: null, reference, derivationPath });
  }
  return Object.freeze({ kind: custody.kind, host: requireString(custody.host, "custody.host"), locator: requireString(custody.locator, "custody.locator"), reference, derivationPath });
}

/**
 * Validates and freezes one wallet relation.
 * @param {object} relation
 * @returns {WalletRelation}
 * @throws {TypeError} When the relation kind is unsupported or the target is missing.
 */
export function normalizeWalletRelation(relation) {
  if (!relation || typeof relation !== "object") throw new TypeError("wallet-registry: relation must be an object");
  if (!RELATION_KINDS.has(relation.kind)) throw new TypeError(`wallet-registry: relation.kind ${relation.kind} is not supported`);
  return Object.freeze({ kind: relation.kind, target: requireString(relation.target, "relation.target") });
}

/**
 * Validates and freezes one provenance source citation. Every row a derivation produces names
 * at least one; a row an operator created (never derived) may carry an `"operator"` source
 * instead.
 * @param {object} source
 * @returns {WalletSource}
 * @throws {TypeError} When the source kind is unsupported or the locator is missing.
 */
export function normalizeWalletSource(source) {
  if (!source || typeof source !== "object") throw new TypeError("wallet-registry: source must be an object");
  if (!SOURCE_KINDS.has(source.kind)) throw new TypeError(`wallet-registry: source.kind ${source.kind} is not supported`);
  return Object.freeze({ kind: source.kind, locator: requireString(source.locator, "source.locator") });
}

/**
 * Validates and freezes a row's label, or passes through `null`. A label exists only when
 * derived from a binding found in the tree -- never a nickname invented for the row -- so
 * `source` is required and must name that binding's carrier.
 * @param {(object|null)} label
 * @returns {(WalletLabel|null)}
 * @throws {TypeError} When a non-null label is missing `text` or `source`.
 */
export function normalizeWalletLabel(label) {
  if (label === null || label === undefined) return null;
  if (typeof label !== "object") throw new TypeError("wallet-registry: label must be an object or null");
  return Object.freeze({ text: requireString(label.text, "label.text"), source: requireString(label.source, "label.source") });
}

/**
 * Validates and freezes one WalletRegistry row. Identity is `{chain, address}`; no row carries a
 * nickname. Unknown custody, an absent label, and an empty source list are never invented --
 * fields absent from the input stay absent rather than being guessed.
 * @param {object} row
 * @returns {WalletRow}
 * @throws {TypeError} When a required field is missing or malformed.
 */
export function normalizeWalletRow(row) {
  if (!row || typeof row !== "object") throw new TypeError("wallet-registry: wallet row must be an object");
  if (!CHAINS.has(row.chain)) throw new TypeError(`wallet-registry: chain ${row.chain} is not supported`);
  const addressPattern = EVM_CHAINS.has(row.chain) ? EVM_ADDRESS_PATTERN : HIVE_ADDRESS_PATTERN;
  const address = requireString(row.address, "address");
  if (!addressPattern.test(address)) throw new TypeError(`wallet-registry: address ${address} is not a valid ${row.chain} address`);
  if (!OWNER_PATTERN.test(row.owner ?? "")) throw new TypeError(`wallet-registry: owner ${row.owner} must be org, founder, enterprise:<name>, or character:<path>`);
  if (!ROLES.has(row.role)) throw new TypeError(`wallet-registry: role ${row.role} is not supported`);
  if (row.balanceReader !== null && row.balanceReader !== undefined && typeof row.balanceReader !== "string") {
    throw new TypeError("wallet-registry: balanceReader must be a string or null");
  }
  const custodies = Object.freeze((row.custodies ?? [row.custody ?? { kind: "unknown", host: null, locator: null }]).map(normalizeWalletCustody));
  if (custodies.length === 0) throw new TypeError("wallet-registry: custodies must name at least one custody entry");
  return Object.freeze({
    chain: row.chain,
    address,
    owner: row.owner,
    role: row.role,
    relations: Object.freeze((row.relations ?? []).map(normalizeWalletRelation)),
    custody: custodies[0],
    custodies,
    balanceReader: row.balanceReader ?? null,
    label: normalizeWalletLabel(row.label ?? null),
    sources: Object.freeze((row.sources ?? []).map(normalizeWalletSource)),
    lastSeen: requireString(row.lastSeen, "lastSeen"),
  });
}

/**
 * Assembles a dated WalletRegistry record from already-normalized wallet rows, sorted by
 * chain then address so the record diffs stably across derivations.
 * @param {{derivedAt: string, wallets: readonly object[]}} input
 * @returns {WalletRegistry}
 * @throws {TypeError} When derivedAt is missing, a row fails normalization, or two rows share
 *   the same `{chain, address}` identity.
 */
export function buildWalletRegistry({ derivedAt, wallets }) {
  requireString(derivedAt, "derivedAt");
  if (!Array.isArray(wallets)) throw new TypeError("wallet-registry: wallets must be an array");
  const normalized = wallets.map(normalizeWalletRow);
  const seen = new Set();
  for (const wallet of normalized) {
    const key = `${wallet.chain}:${addressKey(wallet.chain, wallet.address)}`;
    if (seen.has(key)) throw new TypeError(`wallet-registry: duplicate wallet identity ${key}`);
    seen.add(key);
  }
  normalized.sort((left, right) => (left.chain === right.chain
    ? addressKey(left.chain, left.address).localeCompare(addressKey(right.chain, right.address))
    : left.chain.localeCompare(right.chain)));
  return Object.freeze({ type: "WalletRegistry", version: 1, derivedAt, wallets: Object.freeze(normalized) });
}

/**
 * Finds the one row matching a `{chain, address}` identity, or `undefined`.
 * @param {WalletRegistry} registry
 * @param {{chain: string, address: string}} identity
 * @returns {(WalletRow|undefined)}
 */
export function findWalletRow(registry, { chain, address }) {
  const key = addressKey(chain, address);
  return registry.wallets.find((wallet) => wallet.chain === chain && addressKey(wallet.chain, wallet.address) === key);
}

/**
 * Finds every row whose address matches, across chains (the same address can legitimately
 * appear on more than one EVM chain).
 * @param {WalletRegistry} registry
 * @param {string} address
 * @returns {readonly WalletRow[]}
 */
export function findWalletRowsByAddress(registry, address) {
  return registry.wallets.filter((wallet) => addressKey(wallet.chain, wallet.address) === addressKey(wallet.chain, address));
}

function custodyIdentity(custody) {
  return `${custody.kind}:${custody.host ?? ""}:${custody.locator ?? ""}:${custody.reference ?? ""}:${custody.derivationPath ?? ""}`;
}

/**
 * Folds observations of the same `{chain, address}` identity from more than one source (e.g. a
 * house carrier plus a live host derivation, or two hosts' own derivations) into one row: custody
 * entries, sources, and relations union (deduplicated); a specific owner wins over the generic
 * `"org"` default; the first non-null label and balance reader win; `lastSeen` takes the later
 * timestamp. Never invents a field neither observation carried.
 * @param {readonly object[]} rows Already-normalized WalletRow objects (see `normalizeWalletRow`).
 * @returns {readonly WalletRow[]}
 */
export function mergeWalletObservations(rows) {
  const byIdentity = new Map();
  for (const row of rows) {
    const key = `${row.chain}:${addressKey(row.chain, row.address)}`;
    const existing = byIdentity.get(key);
    if (!existing) {
      byIdentity.set(key, { ...row, custodies: [...row.custodies], sources: [...row.sources], relations: [...row.relations] });
      continue;
    }
    const seenCustody = new Set(existing.custodies.map(custodyIdentity));
    for (const custody of row.custodies) if (!seenCustody.has(custodyIdentity(custody))) { existing.custodies.push(custody); seenCustody.add(custodyIdentity(custody)); }
    const seenSource = new Set(existing.sources.map((source) => `${source.kind}:${source.locator}`));
    for (const source of row.sources) if (!seenSource.has(`${source.kind}:${source.locator}`)) { existing.sources.push(source); seenSource.add(`${source.kind}:${source.locator}`); }
    const seenRelation = new Set(existing.relations.map((relation) => `${relation.kind}:${relation.target}`));
    for (const relation of row.relations) if (!seenRelation.has(`${relation.kind}:${relation.target}`)) { existing.relations.push(relation); seenRelation.add(`${relation.kind}:${relation.target}`); }
    if (existing.owner === "org" && row.owner !== "org") existing.owner = row.owner;
    if (!existing.label && row.label) existing.label = row.label;
    if (!existing.balanceReader && row.balanceReader) existing.balanceReader = row.balanceReader;
    if (row.lastSeen > existing.lastSeen) existing.lastSeen = row.lastSeen;
  }
  return [...byIdentity.values()].map((row) => normalizeWalletRow({ ...row, custody: undefined }));
}

export const WALLET_CHAINS = Object.freeze([...CHAINS]);
export const WALLET_ROLES = Object.freeze([...ROLES]);
export const WALLET_CUSTODY_KINDS = Object.freeze([...CUSTODY_KINDS]);
export const WALLET_SOURCE_KINDS = Object.freeze([...SOURCE_KINDS]);
