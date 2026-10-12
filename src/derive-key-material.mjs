import { HDNodeWallet, Mnemonic, Wallet, getAddress, wordlists } from "ethers";
import { PrivateKey } from "@red-cup-engineering/hive-blockchain-client-service/keys.mjs";

const EVM_PRIVATE_KEY_PATTERN = /^(0x)?[0-9a-fA-F]{64}$/u;
const HIVE_WIF_PATTERN = /^5[1-9A-HJ-NP-Za-km-z]{50}$/u;
const EVM_ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/u;
const HIVE_ACCOUNT_NAME_PATTERN = /^[a-z][a-z0-9.-]{2,15}$/u;
const BIP39_WORD_COUNTS = Object.freeze([12, 15, 18, 21, 24]);
const DEFAULT_EVM_MNEMONIC_PATH = "m/44'/60'/0'/0";
const DEFAULT_MNEMONIC_DERIVATION_COUNT = 10;
const MNEMONIC_WORDLIST = wordlists.en;

function unquoteAndTrim(value) {
  const trimmed = typeof value === "string" ? value.trim() : "";
  const isQuoted = trimmed.length >= 2
    && ((trimmed[0] === '"' && trimmed.at(-1) === '"') || (trimmed[0] === "'" && trimmed.at(-1) === "'"));
  return isQuoted ? trimmed.slice(1, -1).trim() : trimmed;
}

/**
 * Strips surrounding single/double quotes and whitespace from a raw string (normally an
 * environment variable's value read straight from `.env`-shaped text). Pure string
 * transformation -- never logs, prints, or interprets the value.
 * @param {string} value
 * @returns {string}
 */
export function cleanEnvValue(value) {
  return unquoteAndTrim(value);
}

function normalizeMnemonicPhrase(phrase) {
  return typeof phrase === "string" ? unquoteAndTrim(phrase).split(/\s+/u).filter(Boolean).join(" ") : "";
}

export { normalizeMnemonicPhrase };

function looksLikeEvmKeystoreJson(value) {
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    return false;
  }
  return Boolean(parsed) && typeof parsed === "object" && Number(parsed.version) === 3 && Boolean(parsed.crypto ?? parsed.Crypto);
}

/**
 * Checks whether a string is a checksummed BIP-39 mnemonic in the English wordlist: 12, 15, 18,
 * 21, or 24 whitespace-separated words, every word in the wordlist, and the embedded checksum
 * bits valid (ethers `Mnemonic.isValidMnemonic`). Never logs, prints, or returns the phrase.
 * @param {string} phrase
 * @returns {boolean}
 */
export function isValidBip39Mnemonic(phrase) {
  const normalized = normalizeMnemonicPhrase(phrase);
  if (normalized.length === 0) return false;
  const wordCount = normalized.split(" ").length;
  if (!BIP39_WORD_COUNTS.includes(wordCount)) return false;
  return Mnemonic.isValidMnemonic(normalized, MNEMONIC_WORDLIST);
}

/**
 * Classifies one string (normally an environment variable's value) as an EVM private key, a
 * Hive private WIF, a bare EVM address, a Hive account name, a checksummed BIP-39 mnemonic, an
 * Ethereum keystore v3 JSON document, or none of these. Pure pattern matching -- never logs,
 * prints, or returns the value itself; the caller decides what to do with a private-key-shaped
 * classification (derive the public material and discard the input). Tolerates surrounding
 * single/double quotes and whitespace, so a value read straight from an environment file (quoted
 * or not) classifies the same way.
 * @param {string} value
 * @returns {("evm-private-key"|"hive-wif"|"evm-address"|"hive-account"|"bip39-mnemonic"|"evm-keystore-json"|null)}
 */
export function classifyEnvValue(value) {
  if (typeof value !== "string" || value.length === 0) return null;
  const trimmed = unquoteAndTrim(value);
  if (trimmed.length === 0) return null;
  if (EVM_PRIVATE_KEY_PATTERN.test(trimmed)) return "evm-private-key";
  if (HIVE_WIF_PATTERN.test(trimmed)) return "hive-wif";
  if (EVM_ADDRESS_PATTERN.test(trimmed)) return "evm-address";
  if (isValidBip39Mnemonic(trimmed)) return "bip39-mnemonic";
  if (HIVE_ACCOUNT_NAME_PATTERN.test(trimmed)) return "hive-account";
  if (looksLikeEvmKeystoreJson(trimmed)) return "evm-keystore-json";
  return null;
}

/**
 * Derives the checksummed EVM address for a private key. Never echoes the input, including in
 * its thrown message, when the value does not parse. Tolerates surrounding quotes/whitespace.
 * @param {string} privateKey
 * @returns {string} The checksummed `0x...` address.
 * @throws {Error} When the value does not parse as an EVM private key.
 */
export function deriveEvmAddressFromPrivateKey(privateKey) {
  const trimmed = unquoteAndTrim(privateKey);
  try {
    return new Wallet(trimmed.startsWith("0x") ? trimmed : `0x${trimmed}`).address;
  } catch {
    throw new Error("derive-key-material: value does not parse as an EVM private key");
  }
}

/**
 * Derives the STM-prefixed public key for a Hive WIF. Never echoes the input, including in its
 * thrown message, when the value does not parse. A public key is not itself a Hive address (an
 * account name); resolving the owning account requires a chain lookup, done by the caller.
 * @param {string} wif
 * @returns {string} The STM-prefixed public key.
 * @throws {Error} When the value does not parse as a Hive WIF.
 */
export function deriveHivePublicKeyFromWif(wif) {
  const trimmed = typeof wif === "string" ? wif.trim() : "";
  try {
    return PrivateKey.from(trimmed).createPublic().toString();
  } catch {
    throw new Error("derive-key-material: value does not parse as a Hive WIF");
  }
}

/**
 * Extracts the checksummed EVM address from an Ethereum keystore v3 JSON document's own
 * plaintext `address` field -- never decrypts the keystore's `crypto` section, so no passphrase
 * is needed or accepted here. Never echoes the input, including in its thrown message, when the
 * value does not parse.
 * @param {string} value
 * @returns {string} The checksummed `0x...` address.
 * @throws {Error} When the value is not valid keystore v3 JSON or carries no plaintext address.
 */
export function deriveEvmAddressFromKeystoreJson(value) {
  let parsed;
  try {
    parsed = JSON.parse(unquoteAndTrim(value));
  } catch {
    throw new Error("derive-key-material: value does not parse as JSON");
  }
  const rawAddress = typeof parsed?.address === "string" ? parsed.address : null;
  if (!rawAddress) throw new Error("derive-key-material: keystore JSON carries no plaintext address field");
  try {
    return getAddress(`0x${rawAddress.replace(/^0x/u, "")}`);
  } catch {
    throw new Error("derive-key-material: keystore JSON address field does not parse as an EVM address");
  }
}

/**
 * Derives the checksummed EVM address a BIP-39 mnemonic produces at one exact derivation path.
 * Never echoes the phrase or passphrase, including in its thrown message.
 * @param {string} phrase
 * @param {{passphrase?: (string|null), path: string}} input
 * @returns {string} The checksummed `0x...` address.
 * @throws {Error} When the phrase does not checksum-validate or `path` is missing.
 */
export function deriveEvmAddressFromMnemonicAtPath(phrase, { passphrase, path } = {}) {
  const normalized = normalizeMnemonicPhrase(phrase);
  if (!isValidBip39Mnemonic(normalized)) {
    throw new Error("derive-key-material: value does not parse as a checksummed BIP-39 mnemonic");
  }
  if (typeof path !== "string" || path.length === 0) {
    throw new Error("derive-key-material: derivationPath must be a nonempty string");
  }
  return HDNodeWallet.fromPhrase(normalized, passphrase || undefined, path, MNEMONIC_WORDLIST).address;
}

/** @typedef {{index: number, derivationPath: string, address: string}} MnemonicDerivedAddress */
/**
 * Derives `count` sequential EVM addresses from a BIP-39 mnemonic under `path/{0..count-1}`
 * (default `m/44'/60'/0'/0/{0..9}`, the standard EVM external chain). An optional passphrase
 * (BIP-39 §"Passphrase") is honored in memory only -- never echoed. Never echoes the phrase or
 * passphrase, including in a thrown message.
 * @param {string} phrase
 * @param {{passphrase?: (string|null), path?: string, count?: number}} [options]
 * @returns {readonly MnemonicDerivedAddress[]}
 * @throws {Error} When the phrase does not checksum-validate.
 */
export function deriveEvmAddressesFromMnemonic(phrase, { passphrase, path = DEFAULT_EVM_MNEMONIC_PATH, count = DEFAULT_MNEMONIC_DERIVATION_COUNT } = {}) {
  const addresses = [];
  for (let index = 0; index < count; index += 1) {
    const derivationPath = `${path}/${index}`;
    addresses.push(Object.freeze({ index, derivationPath, address: deriveEvmAddressFromMnemonicAtPath(phrase, { passphrase, path: derivationPath }) }));
  }
  return Object.freeze(addresses);
}

export const EVM_ADDRESS_TEST_PATTERN = EVM_ADDRESS_PATTERN;
export const HIVE_ACCOUNT_NAME_TEST_PATTERN = HIVE_ACCOUNT_NAME_PATTERN;
export const BIP39_MNEMONIC_WORD_COUNTS = BIP39_WORD_COUNTS;
export const DEFAULT_EVM_MNEMONIC_DERIVATION_PATH = DEFAULT_EVM_MNEMONIC_PATH;
export const DEFAULT_MNEMONIC_DERIVATION_ADDRESS_COUNT = DEFAULT_MNEMONIC_DERIVATION_COUNT;
