import { basename, join } from "node:path";

import { EVM_CHAINS } from "../data/chains.mjs";
const EXTENSION_BY_CHAIN = Object.freeze(Object.fromEntries(EVM_CHAINS.map((chain) => [chain, "json"])));
const ID_PATTERN = /^[a-z0-9][a-z0-9-]*$/u;

/**
 * The file extension a chain's key material is written under: `json` for an Ethereum keystore
 * v3 document (base, ethereum, arbitrum, avalanche). Hive keys live in the Hive keystore (src/hive-keystore.mjs).
 * @param {string} chain
 * @returns {"json"}
 * @throws {TypeError} When the chain is not one this section custodies.
 */
export function extensionForChain(chain) {
  const extension = EXTENSION_BY_CHAIN[chain];
  if (!extension) throw new TypeError(`keystore-paths: chain ${chain} is not supported`);
  return extension;
}

/**
 * The root house key material is read under: this process's credentials directory (CREDENTIALS_DIRECTORY, rendered
 * from the host's credential store by credential custody), where a wallet keystore is `keys/<chain>/<id>.<ext>`.
 * `directory` names another root, for a test. Never a home directory, never `.env*`, never a path inside the git
 * checkout. With `optional`, a process given no credentials directory gets null.
 * @param {{directory?: string, optional?: boolean}} [input]
 * @returns {string|null}
 */
export function configRoot({ directory = process.env.CREDENTIALS_DIRECTORY, optional = false } = {}) {
  if (directory) return directory;
  if (optional) return null;
  throw new TypeError("keystore-paths: CREDENTIALS_DIRECTORY is not set (this process was not given its host's rendered credentials)");
}

/**
 * The primary key-file path for one wallet: `<configRoot>/keys/<chain>/<id>.<extension>`.
 * @param {{configRoot: string, chain: string, id: string}} input
 * @returns {string}
 * @throws {TypeError} When id is not lowercase kebab-case.
 */
export function keyPath({ configRoot: root, chain, id }) {
  if (!ID_PATTERN.test(id)) throw new TypeError(`keystore-paths: wallet id ${id} must be lowercase kebab-case`);
  return join(root, "keys", chain, `${id}.${extensionForChain(chain)}`);
}

/**
 * The backup key-file path for one wallet, under a separately named backup root:
 * `<backupRoot>/keys/<chain>/<id>.<extension>`.
 * @param {{backupRoot: string, chain: string, id: string}} input
 * @returns {string}
 * @throws {TypeError} When id is not lowercase kebab-case.
 */
export function backupKeyPath({ backupRoot, chain, id }) {
  return keyPath({ configRoot: backupRoot, chain, id });
}

/**
 * Re-roots a known primary key-file path under a backup root, preserving chain and filename.
 * Used when only the registry row's `custody.locator` (not the operator's original filesystem
 * `id`) is known -- a registry row carries no id, only `{chain, address}`.
 * @param {{backupRoot: string, chain: string, locator: string}} input
 * @returns {string}
 */
export function backupKeyPathForLocator({ backupRoot, chain, locator }) {
  return join(backupRoot, "keys", chain, basename(locator));
}

/**
 * The metadata sidecar path for one wallet, beside its primary key file:
 * `<configRoot>/keys/<chain>/<id>.meta.json`. Carries owner/role/relations/createdAt -- never
 * key material.
 * @param {{configRoot: string, chain: string, id: string}} input
 * @returns {string}
 * @throws {TypeError} When id is not lowercase kebab-case.
 */
export function metaPath({ configRoot: root, chain, id }) {
  if (!ID_PATTERN.test(id)) throw new TypeError(`keystore-paths: wallet id ${id} must be lowercase kebab-case`);
  return join(root, "keys", chain, `${id}.meta.json`);
}
