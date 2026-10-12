#!/usr/bin/env node
/**
 * Verifies every WalletRegistry row's custody, per custody entry (a row may carry more than one
 * when known through more than one host or source): a `keystore-file` entry decrypts/parses to
 * the registered address; an `env-on-host` entry re-derives the address in memory (local host) or
 * checks presence only (remote, over SSH). Every other kind is reported `missing`. Never prints,
 * returns, or transmits off its own host any private key byte.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { hostname } from "node:os";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Wallet, isAddress } from "ethers";
import { PrivateKey } from "@red-cup-engineering/hive-blockchain-client-service/keys.mjs";
import {
  classifyEnvValue, deriveEvmAddressFromKeystoreJson, deriveEvmAddressFromMnemonicAtPath,
  deriveEvmAddressFromPrivateKey, deriveHivePublicKeyFromWif,
} from "../src/derive-key-material.mjs";
import { findEnvFilesToScan, findRepoRoot, readEnvVariablesFromFiles } from "./derive-set-of-wallets.mjs";
import { configRoot } from "../src/keystore-paths.mjs";

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

import { EVM_CHAINS as EVM_CHAIN_NAMES } from "../data/chains.mjs";
const EVM_CHAINS = new Set(EVM_CHAIN_NAMES);

function mode0600(path) {
  return (statSync(path).mode & 0o777) === 0o600;
}

/**
 * Local (this host) keystore-file check: file existence, mode 0600, and address agreement. EVM:
 * full decrypt when `passphrase` is supplied, else a structural check against the keystore's own
 * plaintext `address` field. Hive: WIF parse (never password-protected). The backup path is
 * recomputed from the primary locator's own basename under `backupRoot`, matching the layout
 * `create-wallet.mjs` writes (a registry row carries no filesystem id, only `{chain, address}`).
 * @param {{chain: string, address: string, custody: {locator: string}}} wallet
 * @param {{passphrase?: string, backupRoot?: string}} [options]
 * @returns {Promise<{status: ("agreed"|"mismatch"|"missing"), detail: string}>}
 */
export async function verifyLocalKeystoreFile(wallet, { passphrase, backupRoot } = {}) {
  const { locator: primaryPath } = wallet.custody;
  const backupPath = backupRoot ? `${backupRoot}/keys/${wallet.chain}/${basename(primaryPath)}` : null;
  for (const path of [primaryPath, backupPath]) {
    if (!path) continue;
    if (!existsSync(path)) return { status: "missing", detail: `${path} does not exist` };
    if (!mode0600(path)) return { status: "mismatch", detail: `${path} is not mode 0600` };
  }
  try {
    if (EVM_CHAINS.has(wallet.chain)) {
      if (passphrase) {
        const primary = await Wallet.fromEncryptedJson(readFileSync(primaryPath, "utf8"), passphrase);
        if (primary.address.toLowerCase() !== wallet.address.toLowerCase()) return { status: "mismatch", detail: "primary decrypts to a different address" };
        if (backupPath) {
          const backup = await Wallet.fromEncryptedJson(readFileSync(backupPath, "utf8"), passphrase);
          if (backup.address.toLowerCase() !== wallet.address.toLowerCase()) return { status: "mismatch", detail: "backup decrypts to a different address" };
        }
        return { status: "agreed", detail: "primary and backup decrypt to the registered address" };
      }
      const parsed = JSON.parse(readFileSync(primaryPath, "utf8"));
      const plainAddress = typeof parsed.address === "string" ? `0x${parsed.address.replace(/^0x/u, "")}`.toLowerCase() : null;
      if (!plainAddress || !isAddress(plainAddress)) return { status: "missing", detail: "no passphrase supplied and keystore carries no plaintext address to structurally check" };
      return plainAddress === wallet.address.toLowerCase()
        ? { status: "agreed", detail: "keystore plaintext address field agrees (no passphrase supplied, not fully decrypted)" }
        : { status: "mismatch", detail: "keystore plaintext address field disagrees with the registry" };
    }
    const primaryAddress = PrivateKey.from(readFileSync(primaryPath, "utf8").trim()).createPublic().toString();
    if (primaryAddress !== wallet.address) return { status: "mismatch", detail: "primary WIF derives a different public key" };
    if (backupPath) {
      const backupAddress = PrivateKey.from(readFileSync(backupPath, "utf8").trim()).createPublic().toString();
      if (backupAddress !== wallet.address) return { status: "mismatch", detail: "backup WIF derives a different public key" };
    }
    return { status: "agreed", detail: "primary and backup WIF parse to the registered public key" };
  } catch (error) {
    return { status: "mismatch", detail: `custody file did not verify: ${error.message}` };
  }
}

/**
 * Remote keystore-file check: existence and mode only, over SSH, never reading file contents
 * back to this host.
 * @param {{custody: {host: string, locator: string}}} wallet
 * @param {(command: string) => string} [runSsh]
 * @returns {{status: ("agreed"|"missing"), detail: string}}
 */
export function verifyRemoteKeystoreFileExistence(wallet, runSsh = (command) => execFileSync("ssh", ["-o", "BatchMode=yes", "-o", "ConnectTimeout=8", wallet.custody.host, command], { encoding: "utf8" })) {
  const check = `test -f '${wallet.custody.locator}' && stat -c %a '${wallet.custody.locator}' || echo absent`;
  const result = runSsh(check).trim();
  if (result === "600") return { status: "agreed", detail: `${wallet.custody.locator} exists on ${wallet.custody.host} at mode 600` };
  if (result === "absent") return { status: "missing", detail: `${wallet.custody.locator} does not exist on ${wallet.custody.host}` };
  return { status: "mismatch", detail: `${wallet.custody.locator} on ${wallet.custody.host} is mode ${result}, not 600` };
}

/**
 * env-on-host check: only whether the named variable is set on its host, never its value.
 * @param {{custody: {host: string, locator: string}}} wallet
 * @param {(command: string) => string} [runSsh]
 * @returns {{status: ("agreed"|"missing"), detail: string}}
 */
export function verifyEnvOnHost(wallet, runSsh = (command) => execFileSync("ssh", ["-o", "BatchMode=yes", "-o", "ConnectTimeout=8", wallet.custody.host, command], { encoding: "utf8" })) {
  const command = `export XDG_RUNTIME_DIR=/run/user/$(id -u); systemctl --user show-environment | grep -q '^${wallet.custody.locator}=' && echo present || echo absent`;
  const result = runSsh(command).trim();
  return result === "present"
    ? { status: "agreed", detail: `${wallet.custody.locator} is set on ${wallet.custody.host}` }
    : { status: "missing", detail: `${wallet.custody.locator} is not set on ${wallet.custody.host}` };
}

/**
 * Local env-on-host check: re-derives the address (EVM) or public key (Hive) from the named
 * variable's value in this process's own environment, in memory, and compares -- never prints,
 * returns, or logs the value itself. A mnemonic-derived row re-derives at its own recorded
 * `custody.derivationPath`, honoring a companion `<locator>_PASSPHRASE` variable when present. A
 * Hive check compares against `custody.reference` (a previously recorded public key), since an
 * account name needs a chain lookup this does not do.
 * @param {{chain: string, address: string,
 *   custody: {locator: string, reference: (string|null), derivationPath: (string|null)}}} wallet
 * @param {{env?: object}} [options]
 * @returns {{status: ("agreed"|"mismatch"|"missing"), detail: string}}
 */
export function verifyLocalEnvVariable(wallet, { env = process.env } = {}) {
  const value = env[wallet.custody.locator];
  if (value === undefined) return { status: "missing", detail: `${wallet.custody.locator} is not set in this process's environment` };
  try {
    const kind = classifyEnvValue(value);
    if (EVM_CHAINS.has(wallet.chain)) {
      if (kind === "bip39-mnemonic") {
        if (!wallet.custody.derivationPath) return { status: "missing", detail: `${wallet.custody.locator} is a mnemonic, but the registry row carries no derivationPath to re-derive` };
        const passphrase = env[`${wallet.custody.locator}_PASSPHRASE`];
        const derived = deriveEvmAddressFromMnemonicAtPath(value, { passphrase, path: wallet.custody.derivationPath });
        return derived.toLowerCase() === wallet.address.toLowerCase()
          ? { status: "agreed", detail: `${wallet.custody.locator} derives the registered address at ${wallet.custody.derivationPath}` }
          : { status: "mismatch", detail: `${wallet.custody.locator} derives a different address at ${wallet.custody.derivationPath}` };
      }
      if (kind === "evm-keystore-json") {
        const derived = deriveEvmAddressFromKeystoreJson(value);
        return derived.toLowerCase() === wallet.address.toLowerCase()
          ? { status: "agreed", detail: `${wallet.custody.locator} keystore JSON plaintext address field agrees` }
          : { status: "mismatch", detail: `${wallet.custody.locator} keystore JSON plaintext address field disagrees` };
      }
      const derived = deriveEvmAddressFromPrivateKey(value);
      return derived.toLowerCase() === wallet.address.toLowerCase()
        ? { status: "agreed", detail: `${wallet.custody.locator} derives the registered address` }
        : { status: "mismatch", detail: `${wallet.custody.locator} derives a different address` };
    }
    const derivedPublicKey = deriveHivePublicKeyFromWif(value);
    if (!wallet.custody.reference) return { status: "missing", detail: `${wallet.custody.locator} parses, but no recorded public key is available to compare against` };
    return derivedPublicKey === wallet.custody.reference
      ? { status: "agreed", detail: `${wallet.custody.locator} derives the recorded public key` }
      : { status: "mismatch", detail: `${wallet.custody.locator} derives a different public key` };
  } catch (error) {
    return { status: "mismatch", detail: `${wallet.custody.locator} did not derive usable key material: ${error.message}` };
  }
}

/** @typedef {{chain: string, address: string, custodyKind: string, host: (string|null),
 *   status: ("agreed"|"mismatch"|"missing"), detail: string}} CustodyVerificationRow */
/**
 * @typedef {{type: "CustodyVerification", version: 1, verifiedAt: string,
 *   counts: {agreed: number, mismatch: number, missing: number}, rows: readonly CustodyVerificationRow[]}} CustodyVerification
 */

function isLocalHost(host, localHostname) {
  return host === localHostname || host === "bare-cedar-fog";
}

/**
 * Verifies every custody entry of every WalletRegistry row against injected checkers, so the
 * local host, a remote host, and an env-on-host case are each exercised through their own
 * function without this operation itself touching a filesystem or network socket. One row with
 * two custody entries (e.g. known on two hosts) yields two verification rows.
 * @param {{registry: object, localHostname?: string, checkLocalKeystore: Function,
 *   checkRemoteKeystore: Function, checkEnvOnHost: Function, checkLocalEnv?: Function,
 *   now?: () => string}} input
 * @returns {Promise<CustodyVerification>}
 */
export async function verifyWalletCustody({ registry, localHostname = hostname(), checkLocalKeystore, checkRemoteKeystore, checkEnvOnHost, checkLocalEnv = verifyLocalEnvVariable, now = () => new Date().toISOString() }) {
  const rows = [];
  for (const wallet of registry.wallets) {
    for (const custody of wallet.custodies ?? [wallet.custody]) {
      const identified = { ...wallet, custody };
      let result;
      if (custody.kind === "keystore-file") {
        result = isLocalHost(custody.host, localHostname) ? await checkLocalKeystore(identified) : checkRemoteKeystore(identified);
      } else if (custody.kind === "env-on-host") {
        result = isLocalHost(custody.host, localHostname) ? checkLocalEnv(identified) : checkEnvOnHost(identified);
      } else {
        result = { status: "missing", detail: `custody kind ${custody.kind} is not independently verifiable by this operation` };
      }
      rows.push({ chain: wallet.chain, address: wallet.address, custodyKind: custody.kind, host: custody.host, status: result.status, detail: result.detail });
    }
  }
  const counts = rows.reduce((all, row) => ({ ...all, [row.status]: (all[row.status] ?? 0) + 1 }), { agreed: 0, mismatch: 0, missing: 0 });
  return { type: "CustodyVerification", version: 1, verifiedAt: now(), counts, rows };
}

if (import.meta.main) {
  const { parseArgs } = await import("node:util");
  const { values } = parseArgs({ options: { registry: { type: "string" }, "checkout-root": { type: "string" } } });
  if (!values.registry) {
    process.stderr.write("error: --registry <path> is required\n");
    process.exit(2);
  }
  const registry = JSON.parse(readFileSync(values.registry, "utf8"));
  const passphrase = process.env.KEY_PASSPHRASE;
  const backupRoot = process.env.KEY_BACKUP_ROOT;
  const checkoutRoot = values["checkout-root"] ?? findRepoRoot(PACKAGE_ROOT);
  const houseConfigRoot = configRoot({ optional: true });
  const env = { ...readEnvVariablesFromFiles(findEnvFilesToScan({ checkoutRoot, houseConfigRoot })), ...process.env };
  const result = await verifyWalletCustody({
    registry,
    checkLocalKeystore: (wallet) => verifyLocalKeystoreFile(wallet, { passphrase, backupRoot }),
    checkRemoteKeystore: (wallet) => verifyRemoteKeystoreFileExistence(wallet),
    checkEnvOnHost: (wallet) => verifyEnvOnHost(wallet),
    checkLocalEnv: (wallet) => verifyLocalEnvVariable(wallet, { env }),
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (result.counts.mismatch > 0 || result.counts.missing > 0) process.exitCode = 1;
}
