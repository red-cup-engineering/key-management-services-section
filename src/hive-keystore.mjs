// hive-keystore — Hive role keys at rest: <root>/<account>/<role>.wif (plaintext, mode 0600) or
// <role>.wif.enc (sealed under a passphrase), directories mode 0700. This is the layout the
// production host keeps. The root is HIVE_KEY_ROOT, or else `hive/` in this process's credentials
// directory (CREDENTIALS_DIRECTORY, rendered from the host's credential store by credential
// custody); a key stored there is kept in the store. Never a home directory.
import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, chmodSync } from "node:fs";
import path from "node:path";
import { HiveClient } from "@red-cup-engineering/hive-blockchain-client-service";
import { PrivateKey, KEY_ROLES } from "@red-cup-engineering/hive-blockchain-client-service/keys.mjs";
import { sealWithPassphrase, openWithPassphrase } from "@red-cup-engineering/cryptographic-computer-data-engineering-services-section/seal";
import { keepCredential } from "@red-cup-engineering/credential-custody-service/keep";

export { KEY_ROLES };

export function defaultHiveKeyRoot(env = process.env) {
  if (env.HIVE_KEY_ROOT) return env.HIVE_KEY_ROOT;
  if (env.CREDENTIALS_DIRECTORY) return path.join(env.CREDENTIALS_DIRECTORY, "hive");
  throw new Error("hive-keystore: neither HIVE_KEY_ROOT nor CREDENTIALS_DIRECTORY names where Hive keys are");
}

export function hiveKeyDir(account, root = defaultHiveKeyRoot()) {
  return path.join(root, account);
}

/** The plaintext key file for one account role. */
export function hiveKeyPath(account, role, root = defaultHiveKeyRoot()) {
  return path.join(hiveKeyDir(account, root), `${role}.wif`);
}

function sealedKeyPath(account, role, root) {
  return `${hiveKeyPath(account, role, root)}.enc`;
}

/**
 * Store a role key, plaintext or sealed under `passphrase`; never both forms for one role. The file is written at
 * once; a key stored in this process's credentials directory is then kept in the host's credential store.
 */
export async function setHiveKey(account, role, wif, { root = defaultHiveKeyRoot(), passphrase, env = process.env } = {}) {
  try {
    PrivateKey.from(wif);
  } catch (error) {
    throw new TypeError(`hive-keystore: invalid WIF (${error instanceof Error ? error.message : String(error)})`);
  }
  const plain = hiveKeyPath(account, role, root);
  const sealed = sealedKeyPath(account, role, root);
  const target = passphrase ? sealed : plain;
  const other = passphrase ? plain : sealed;
  if (existsSync(other)) throw new Error(`hive-keystore: ${path.basename(other)} already exists; remove it before storing the other form`);
  mkdirSync(hiveKeyDir(account, root), { recursive: true, mode: 0o700 });
  writeFileSync(target, passphrase ? sealWithPassphrase(wif, passphrase) : `${wif}\n`, { mode: 0o600 });
  chmodSync(target, 0o600);
  if (env.CREDENTIALS_STORE && env.CREDENTIALS_DIRECTORY && path.resolve(root) === path.resolve(env.CREDENTIALS_DIRECTORY, "hive")) {
    await keepCredential({ id: `hive.${account}.${role}-wif${passphrase ? "-enc" : ""}`, service: "hive-keys", path: path.relative(env.CREDENTIALS_DIRECTORY, target), value: readFileSync(target, "utf8"), kind: "private-key", provider: "hive" }, env);
  }
}

/** The role key's WIF, or undefined when none is stored; a sealed key needs `passphrase`. */
export function loadHiveKey(account, role, { root = defaultHiveKeyRoot(), passphrase } = {}) {
  const plain = hiveKeyPath(account, role, root);
  if (existsSync(plain)) return readFileSync(plain, "utf8").trim() || undefined;
  const sealed = sealedKeyPath(account, role, root);
  if (!existsSync(sealed)) return undefined;
  if (!passphrase) throw new Error(`hive-keystore: ${role} key for @${account} is sealed; a passphrase is required`);
  return openWithPassphrase(readFileSync(sealed, "utf8"), passphrase);
}

/** Which form each role's key is stored in: "plaintext", "sealed" or "absent". */
export function hiveKeyStatus(account, root = defaultHiveKeyRoot()) {
  const dir = hiveKeyDir(account, root);
  const files = existsSync(dir) ? new Set(readdirSync(dir)) : new Set();
  return Object.fromEntries(KEY_ROLES.map((role) => [
    role,
    files.has(`${role}.wif`) ? "plaintext" : files.has(`${role}.wif.enc`) ? "sealed" : "absent",
  ]));
}

/** Whether `wif` alone meets `chainAccount`'s authority threshold for `role` (a get_accounts row). */
export function keySatisfiesAuthority(chainAccount, role, wif) {
  const authority = chainAccount?.[role];
  if (!authority) return false;
  const publicKey = PrivateKey.from(wif).createPublic("STM").toString();
  const weight = Number((authority.key_auths ?? []).find(([candidate]) => candidate === publicKey)?.[1] ?? 0);
  return weight >= Number(authority.weight_threshold ?? 1);
}

/**
 * The stored role key as a PrivateKey, refused unless it alone satisfies the account's on-chain
 * authority for that role. Root and passphrase default to HIVE_KEY_ROOT and HIVE_KEY_PASSPHRASE.
 */
export async function loadVerifiedHiveKey(account, role, {
  root = process.env.HIVE_KEY_ROOT || defaultHiveKeyRoot(), passphrase = process.env.HIVE_KEY_PASSPHRASE,
  chainAccount, client = new HiveClient(),
} = {}) {
  const wif = loadHiveKey(account, role, { root, passphrase });
  if (!wif) throw new Error(`hive-keystore: no ${role} key is stored for @${account}`);
  const row = chainAccount ?? await client.getAccount(account);
  if (!keySatisfiesAuthority(row, role, wif)) throw new Error(`hive-keystore: the stored ${role} key does not satisfy @${account}'s ${role} authority`);
  return PrivateKey.from(wif);
}
