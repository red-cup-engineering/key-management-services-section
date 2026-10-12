import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import { Mnemonic } from "ethers";
import {
  classifyEnvValue, deriveEvmAddressesFromMnemonic, deriveEvmAddressFromKeystoreJson,
  deriveEvmAddressFromMnemonicAtPath, deriveEvmAddressFromPrivateKey, isValidBip39Mnemonic,
} from "../src/derive-key-material.mjs";

function throwawayMnemonic(entropyBytes = 16) {
  return Mnemonic.fromEntropy(randomBytes(entropyBytes)).phrase;
}

test("classifyEnvValue: a freshly generated 12-word mnemonic classifies as bip39-mnemonic", () => {
  const phrase = throwawayMnemonic();
  assert.equal(classifyEnvValue(phrase), "bip39-mnemonic");
  assert.equal(isValidBip39Mnemonic(phrase), true);
});

test("classifyEnvValue: a 24-word mnemonic classifies as bip39-mnemonic", () => {
  const phrase = throwawayMnemonic(32);
  assert.equal(phrase.split(" ").length, 24);
  assert.equal(classifyEnvValue(phrase), "bip39-mnemonic");
});

test("classifyEnvValue and isValidBip39Mnemonic refuse a tampered (bad-checksum) phrase", () => {
  const words = throwawayMnemonic().split(" ");
  words[0] = words[0] === "abandon" ? "ability" : "abandon";
  const tampered = words.join(" ");
  assert.equal(isValidBip39Mnemonic(tampered), false);
  assert.equal(classifyEnvValue(tampered), null);
});

test("classifyEnvValue refuses prose that merely has 12 words", () => {
  const prose = "the quick brown fox jumps over the lazy dog again and again";
  assert.equal(prose.split(" ").length, 12);
  assert.equal(classifyEnvValue(prose), null);
});

test("classifyEnvValue: an EVM private key surrounded by quotes and whitespace still classifies", () => {
  const key = "0x1111111111111111111111111111111111111111111111111111111111111111".slice(0, 66);
  assert.equal(classifyEnvValue(`  "${key}"  `), "evm-private-key");
  assert.equal(classifyEnvValue(`'${key}'`), "evm-private-key");
  assert.equal(deriveEvmAddressFromPrivateKey(`  "${key}"  `), deriveEvmAddressFromPrivateKey(key));
});

test("classifyEnvValue: a keystore v3 JSON string classifies as evm-keystore-json", () => {
  const keystore = JSON.stringify({ address: "abababababababababababababababababababab", crypto: { cipher: "aes-128-ctr" }, version: 3 });
  assert.equal(classifyEnvValue(keystore), "evm-keystore-json");
});

test("deriveEvmAddressFromKeystoreJson: extracts the plaintext address without decrypting", () => {
  const keystore = JSON.stringify({ address: "0x0000000000000000000000000000000000000abc", crypto: { cipher: "aes-128-ctr" }, version: 3 });
  const address = deriveEvmAddressFromKeystoreJson(keystore);
  assert.match(address, /^0x[0-9a-fA-F]{40}$/u);
});

test("deriveEvmAddressFromKeystoreJson throws on non-keystore JSON, never echoing the input", () => {
  assert.throws(() => deriveEvmAddressFromKeystoreJson(JSON.stringify({ hello: "world" })), /does not parse|carries no plaintext address/u);
});

test("deriveEvmAddressesFromMnemonic: a checksummed phrase derives 10 addresses at the standard EVM path", () => {
  const phrase = throwawayMnemonic();
  const addresses = deriveEvmAddressesFromMnemonic(phrase);
  assert.equal(addresses.length, 10);
  addresses.forEach((entry, index) => {
    assert.equal(entry.index, index);
    assert.equal(entry.derivationPath, `m/44'/60'/0'/0/${index}`);
    assert.match(entry.address, /^0x[0-9a-fA-F]{40}$/u);
  });
  const uniqueAddresses = new Set(addresses.map((entry) => entry.address));
  assert.equal(uniqueAddresses.size, 10);
});

test("deriveEvmAddressesFromMnemonic: the same phrase derives the same addresses deterministically", () => {
  const phrase = throwawayMnemonic();
  const first = deriveEvmAddressesFromMnemonic(phrase);
  const second = deriveEvmAddressesFromMnemonic(phrase);
  assert.deepEqual(first.map((entry) => entry.address), second.map((entry) => entry.address));
});

test("deriveEvmAddressesFromMnemonic: a passphrase changes every derived address", () => {
  const phrase = throwawayMnemonic();
  const withoutPassphrase = deriveEvmAddressesFromMnemonic(phrase);
  const withPassphrase = deriveEvmAddressesFromMnemonic(phrase, { passphrase: "a throwaway test passphrase" });
  for (let index = 0; index < 10; index += 1) {
    assert.notEqual(withoutPassphrase[index].address, withPassphrase[index].address);
  }
});

test("deriveEvmAddressFromMnemonicAtPath: agrees with the corresponding entry from deriveEvmAddressesFromMnemonic", () => {
  const phrase = throwawayMnemonic();
  const addresses = deriveEvmAddressesFromMnemonic(phrase);
  const singleLookup = deriveEvmAddressFromMnemonicAtPath(phrase, { path: addresses[3].derivationPath });
  assert.equal(singleLookup, addresses[3].address);
});

test("deriveEvmAddressesFromMnemonic refuses a tampered mnemonic, never echoing it in the thrown message", () => {
  const words = throwawayMnemonic().split(" ");
  words[0] = words[0] === "abandon" ? "ability" : "abandon";
  const tampered = words.join(" ");
  assert.throws(() => deriveEvmAddressesFromMnemonic(tampered), (error) => {
    assert.match(error.message, /does not parse as a checksummed BIP-39 mnemonic/u);
    assert.ok(!error.message.includes(tampered));
    return true;
  });
});
