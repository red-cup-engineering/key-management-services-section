import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { randomBytes } from "node:crypto";
import { Mnemonic, Wallet } from "ethers";
import { PrivateKey } from "@red-cup-engineering/hive-blockchain-client-service/keys.mjs";
import {
  carrierRowsFromFacts, deriveWalletRegistry, enrichRowsWithTreeRelations, enterpriseRowFromBinding,
  findEnvFilesToScan, findEnvVariableConsumers, findOwnerBindingsForAddresses, findRepoRoot,
  mergeHostReadouts, readEnvVariablesFromFiles, scanEnvironmentForWalletFacts,
  scanKeystoreDirectoriesForWalletFacts, slugFromSettlementRoot,
} from "../scripts/derive-set-of-wallets.mjs";
import { normalizeWalletRow } from "../src/wallet-registry.mjs";

function throwawayMnemonic(entropyBytes = 16) {
  return Mnemonic.fromEntropy(randomBytes(entropyBytes)).phrase;
}

const HERE = dirname(fileURLToPath(import.meta.url));
const FACTS_PATH = join(HERE, "..", "data", "records", "wallet-facts-source-records", "2026-09-05-wallet-facts-source.json");

function tempDir(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

test("the bundled wallet-facts-source.json carries no nickname id on any row", () => {
  const facts = JSON.parse(readFileSync(FACTS_PATH, "utf8"));
  assert.equal(facts.hiveAccounts.length, 6);
  assert.equal(facts.baseWallets.length, 10);
  assert.ok(facts.baseWallets.every((wallet) => wallet.id === undefined));
  assert.ok(facts.baseWallets.every((wallet) => /^0x[0-9a-fA-F]{40}$/u.test(wallet.address)));
  assert.ok([...facts.hiveAccounts, ...facts.baseWallets].every((row) => typeof row.source === "string" && row.source.length > 0));
});

test("slugFromSettlementRoot lowercases and kebabs the settlement root's final path segment", () => {
  assert.equal(slugFromSettlementRoot("services/x/lib/legacy/2026-07-20-infomaterial-observation-v1"), "2026-07-20-infomaterial-observation-v1");
});

test("enterpriseRowFromBinding carries no id, cites the settlement root as its source", () => {
  const binding = { chain: { chainId: 8453 }, account: { address: "0x0000000000000000000000000000000000000005" }, policy: { custody: "settlement-private", signer: "0x0000000000000000000000000000000000000006" } };
  const row = enterpriseRowFromBinding({ nodeId: "some-enterprise", root: "services/some-enterprise" }, binding, "2026-09-05T00:00:00Z");
  assert.equal(row.id, undefined);
  assert.equal(row.owner, "enterprise:some-enterprise");
  assert.deepEqual(row.sources, [{ kind: "ethereum-census", locator: "services/some-enterprise" }]);
});

test("enterpriseRowFromBinding marks kms custody only when the binding's own policy says so", () => {
  const settlement = { nodeId: "some-enterprise", root: "services/some-enterprise" };
  const binding = { chain: { chainId: 8453 }, account: { address: "0x0000000000000000000000000000000000000005" }, policy: { custody: "remote-cloud-kms-hsm", signer: "0x0000000000000000000000000000000000000006", keyVersion: "projects/p/locations/l/keyRings/k/cryptoKeys/c/cryptoKeyVersions/1" } };
  const row = enterpriseRowFromBinding(settlement, binding, "2026-09-05T00:00:00Z");
  assert.equal(row.custody.kind, "kms");
});

test("deriveWalletRegistry: two settlements binding the same address merge into one row, not two", async () => {
  const sharedBinding = { chain: { chainId: 31337 }, account: { address: "0x0000000000000000000000000000000000000010" }, policy: { custody: "settlement-private", signer: "0x0000000000000000000000000000000000000011" } };
  const census = { workspace: "/tree", settlements: [{ nodeId: "shared-node", root: "services/a", status: "bound" }, { nodeId: "shared-node", root: "services/b", status: "bound" }] };
  const { registry } = await deriveWalletRegistry({
    derivedAt: "2026-09-05T00:00:00Z", host: "bare-cedar-fog", census,
    envVariables: {}, resolveHiveAccount: async () => null,
    keystoreConfigRoot: tempDir("keys-empty-"), keystoreBackupRoot: null, checkoutRoot: null,
    carrierFacts: { hiveAccounts: [], baseWallets: [] },
    readBindingFiles: () => [sharedBinding],
  });
  assert.equal(registry.wallets.length, 1);
  assert.equal(registry.wallets[0].sources.length, 2);
});

test("scanEnvironmentForWalletFacts: an EVM private key derives its address and never returns the key", async () => {
  const wallet = Wallet.createRandom();
  const { rows, unresolved } = await scanEnvironmentForWalletFacts({
    variables: { SOME_EVM_KEY: wallet.privateKey, UNRELATED: "just some prose, not a key" },
    host: "bare-cedar-fog", derivedAt: "2026-09-05T00:00:00Z", resolveHiveAccount: async () => null,
  });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].address.toLowerCase(), wallet.address.toLowerCase());
  assert.equal(rows[0].custody.locator, "SOME_EVM_KEY");
  assert.equal(rows[0].custody.kind, "env-on-host");
  assert.equal(rows[0].sources[0].kind, "env-private-key");
  assert.equal(unresolved.length, 0);
  assert.ok(!JSON.stringify(rows).includes(wallet.privateKey.replace(/^0x/u, "")));
});

test("scanEnvironmentForWalletFacts: a bare EVM address is recorded with unknown custody and a public reference", async () => {
  const { rows } = await scanEnvironmentForWalletFacts({
    variables: { KNOWN_PUBLIC_ADDRESS: "0x0000000000000000000000000000000000000099" },
    host: "bare-cedar-fog", derivedAt: "2026-09-05T00:00:00Z", resolveHiveAccount: async () => null,
  });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].custody.kind, "unknown");
  assert.equal(rows[0].custody.reference, "KNOWN_PUBLIC_ADDRESS");
});

test("scanEnvironmentForWalletFacts: a Hive WIF whose account cannot be resolved contributes no row", async () => {
  const wif = new PrivateKey(randomBytes(32)).toString();
  const { rows, unresolved } = await scanEnvironmentForWalletFacts({
    variables: { SOME_HIVE_KEY: wif },
    host: "bare-cedar-fog", derivedAt: "2026-09-05T00:00:00Z", resolveHiveAccount: async () => null,
  });
  assert.equal(rows.length, 0);
  assert.equal(unresolved.length, 1);
  assert.equal(unresolved[0].locator, "SOME_HIVE_KEY");
  assert.ok(typeof unresolved[0].publicKey === "string" && unresolved[0].publicKey.startsWith("STM"));
});

test("scanEnvironmentForWalletFacts: a checksummed mnemonic derives 10 base-chain env-on-host rows, one per index", async () => {
  const phrase = throwawayMnemonic();
  const { rows, unresolved } = await scanEnvironmentForWalletFacts({
    variables: { A_SEED_PHRASE: phrase },
    host: "bare-cedar-fog", derivedAt: "2026-09-05T00:00:00Z", resolveHiveAccount: async () => null,
  });
  assert.equal(rows.length, 10);
  assert.equal(unresolved.length, 0);
  assert.ok(rows.every((row) => row.chain === "base"));
  assert.ok(rows.every((row) => row.custody.kind === "env-on-host" && row.custody.locator === "A_SEED_PHRASE"));
  assert.deepEqual(rows.map((row) => row.custody.derivationPath), Array.from({ length: 10 }, (_, index) => `m/44'/60'/0'/0/${index}`));
  assert.ok(!JSON.stringify(rows).includes(phrase));
  const uniqueAddresses = new Set(rows.map((row) => row.address));
  assert.equal(uniqueAddresses.size, 10);
});

test("scanEnvironmentForWalletFacts: a companion <name>_PASSPHRASE variable changes the derived addresses", async () => {
  const phrase = throwawayMnemonic();
  const withoutPassphrase = await scanEnvironmentForWalletFacts({
    variables: { A_SEED_PHRASE: phrase },
    host: "bare-cedar-fog", derivedAt: "2026-09-05T00:00:00Z", resolveHiveAccount: async () => null,
  });
  const withPassphrase = await scanEnvironmentForWalletFacts({
    variables: { A_SEED_PHRASE: phrase, A_SEED_PHRASE_PASSPHRASE: "a throwaway test passphrase" },
    host: "bare-cedar-fog", derivedAt: "2026-09-05T00:00:00Z", resolveHiveAccount: async () => null,
  });
  assert.equal(withoutPassphrase.rows.length, 10);
  assert.equal(withPassphrase.rows.length, 10);
  assert.notDeepEqual(withoutPassphrase.rows.map((row) => row.address), withPassphrase.rows.map((row) => row.address));
});

test("scanEnvironmentForWalletFacts: a tampered (bad-checksum) mnemonic-shaped value contributes no row", async () => {
  const words = throwawayMnemonic().split(" ");
  words[0] = words[0] === "abandon" ? "ability" : "abandon";
  const { rows, unresolved } = await scanEnvironmentForWalletFacts({
    variables: { A_SEED_PHRASE: words.join(" ") },
    host: "bare-cedar-fog", derivedAt: "2026-09-05T00:00:00Z", resolveHiveAccount: async () => null,
  });
  assert.equal(rows.length, 0);
  assert.equal(unresolved.length, 0);
});

test("scanEnvironmentForWalletFacts: an env-sat keystore v3 JSON string derives its plaintext address", async () => {
  const keystore = JSON.stringify({ address: "0x0000000000000000000000000000000000000fed", crypto: { cipher: "aes-128-ctr" }, version: 3 });
  const { rows } = await scanEnvironmentForWalletFacts({
    variables: { A_KEYSTORE_JSON: keystore },
    host: "bare-cedar-fog", derivedAt: "2026-09-05T00:00:00Z", resolveHiveAccount: async () => null,
  });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].custody.kind, "env-on-host");
  assert.equal(rows[0].custody.locator, "A_KEYSTORE_JSON");
  assert.match(rows[0].address, /^0x[0-9a-fA-F]{40}$/u);
});

test("findEnvFilesToScan: lists .env, every .env.* sibling, and every *.env under the house config root, sorted", () => {
  const checkoutRoot = tempDir("checkout-root-");
  const houseConfigRoot = tempDir("house-config-root-");
  writeFileSync(join(checkoutRoot, ".env"), "X=1\n");
  writeFileSync(join(checkoutRoot, ".env.local"), "Y=2\n");
  writeFileSync(join(checkoutRoot, "not-an-env-file.txt"), "z\n");
  writeFileSync(join(houseConfigRoot, "ops-mcp-client.env"), "Z=3\n");
  try {
    const paths = findEnvFilesToScan({ checkoutRoot, houseConfigRoot });
    assert.deepEqual(paths, [
      join(checkoutRoot, ".env"),
      join(checkoutRoot, ".env.local"),
      join(houseConfigRoot, "ops-mcp-client.env"),
    ].sort());
  } finally {
    rmSync(checkoutRoot, { recursive: true, force: true });
    rmSync(houseConfigRoot, { recursive: true, force: true });
  }
});

test("findEnvFilesToScan: a missing checkout .env and a missing house config root are simply absent", () => {
  const checkoutRoot = tempDir("checkout-root-empty-");
  try {
    assert.deepEqual(findEnvFilesToScan({ checkoutRoot, houseConfigRoot: join(checkoutRoot, "does-not-exist") }), []);
  } finally {
    rmSync(checkoutRoot, { recursive: true, force: true });
  }
});

test("readEnvVariablesFromFiles: merges variables across files, later files winning on a name collision", () => {
  const dir = tempDir("env-files-");
  writeFileSync(join(dir, "a.env"), "SHARED=first\nONLY_A=1\n");
  writeFileSync(join(dir, "b.env"), "SHARED=second\nONLY_B=2\n");
  try {
    const variables = readEnvVariablesFromFiles([join(dir, "a.env"), join(dir, "b.env")]);
    assert.equal(variables.SHARED, "second");
    assert.equal(variables.ONLY_A, "1");
    assert.equal(variables.ONLY_B, "2");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("scanKeystoreDirectoriesForWalletFacts: an EVM keystore's plaintext address and its meta.json sidecar are read", () => {
  const configRoot = tempDir("keys-config-");
  const keysDir = join(configRoot, "keys", "base");
  mkdirSync(keysDir, { recursive: true });
  writeFileSync(join(keysDir, "some-wallet.json"), JSON.stringify({ address: "0000000000000000000000000000000000000042" }));
  writeFileSync(join(keysDir, "some-wallet.meta.json"), JSON.stringify({ id: "some-wallet", owner: "org", role: "auxiliary", relations: [{ kind: "consumed-by", target: "example" }] }));
  try {
    const rows = scanKeystoreDirectoriesForWalletFacts({ configRoot, backupRoot: null, host: "bare-cedar-fog", derivedAt: "2026-09-05T00:00:00Z" });
    assert.equal(rows.length, 1);
    assert.equal(rows[0].address, "0x0000000000000000000000000000000000000042");
    assert.equal(rows[0].owner, "org");
    assert.deepEqual(rows[0].relations, [{ kind: "consumed-by", target: "example" }]);
    assert.equal(rows[0].id, undefined);
  } finally {
    rmSync(configRoot, { recursive: true, force: true });
  }
});

test("scanKeystoreDirectoriesForWalletFacts: a backup file at the same filename becomes a second custody entry", () => {
  const configRoot = tempDir("keys-config-");
  const backupRoot = tempDir("keys-backup-");
  for (const root of [configRoot, backupRoot]) mkdirSync(join(root, "keys", "base"), { recursive: true });
  const contents = JSON.stringify({ address: "0000000000000000000000000000000000000043" });
  writeFileSync(join(configRoot, "keys", "base", "another-wallet.json"), contents);
  writeFileSync(join(backupRoot, "keys", "base", "another-wallet.json"), contents);
  try {
    const rows = scanKeystoreDirectoriesForWalletFacts({ configRoot, backupRoot, host: "bare-cedar-fog", derivedAt: "2026-09-05T00:00:00Z" });
    assert.equal(rows[0].custodies.length, 2);
  } finally {
    rmSync(configRoot, { recursive: true, force: true });
    rmSync(backupRoot, { recursive: true, force: true });
  }
});

test("findEnvVariableConsumers: finds the package whose source reads process.env.<name>", () => {
  const checkoutRoot = tempDir("tree-root-");
  const packageDir = join(checkoutRoot, "some-package");
  mkdirSync(packageDir, { recursive: true });
  writeFileSync(join(packageDir, "package.json"), JSON.stringify({ name: "@example/some-package" }));
  writeFileSync(join(packageDir, "index.mjs"), "export const key = process.env.EXAMPLE_KEY_NAME;\n");
  try {
    assert.deepEqual(findEnvVariableConsumers({ name: "EXAMPLE_KEY_NAME", checkoutRoot }), ["@example/some-package"]);
    assert.deepEqual(findEnvVariableConsumers({ name: "NO_SUCH_VARIABLE", checkoutRoot }), []);
  } finally {
    rmSync(checkoutRoot, { recursive: true, force: true });
  }
});

test("findOwnerBindingsForAddresses: an address named in a package.json resolves to an enterprise owner", () => {
  const checkoutRoot = tempDir("tree-root-");
  const packageDir = join(checkoutRoot, "some-enterprise");
  mkdirSync(packageDir, { recursive: true });
  writeFileSync(join(packageDir, "package.json"), JSON.stringify({ name: "@example/some-enterprise", account: "0x0000000000000000000000000000000000000077" }));
  try {
    const bindings = findOwnerBindingsForAddresses({ addresses: ["0x0000000000000000000000000000000000000077"], checkoutRoot });
    assert.deepEqual(bindings["0x0000000000000000000000000000000000000077"], { kind: "enterprise", value: "@example/some-enterprise" });
  } finally {
    rmSync(checkoutRoot, { recursive: true, force: true });
  }
});

test("findOwnerBindingsForAddresses: an address named under an agency characters entry resolves to a character owner", () => {
  const checkoutRoot = tempDir("tree-root-");
  const charactersDir = join(checkoutRoot, "some-section", "lib", "agency", "characters");
  mkdirSync(charactersDir, { recursive: true });
  writeFileSync(join(charactersDir, "Example Character.md"), "wallet: 0x0000000000000000000000000000000000000088\n");
  try {
    const bindings = findOwnerBindingsForAddresses({ addresses: ["0x0000000000000000000000000000000000000088"], checkoutRoot });
    assert.equal(bindings["0x0000000000000000000000000000000000000088"].kind, "character");
    assert.match(bindings["0x0000000000000000000000000000000000000088"].value, /agency\/characters\/Example Character\.md$/u);
  } finally {
    rmSync(checkoutRoot, { recursive: true, force: true });
  }
});

test("findOwnerBindingsForAddresses: an address bound nowhere in the tree is simply absent (never guessed as org)", () => {
  const checkoutRoot = tempDir("tree-root-");
  try {
    const bindings = findOwnerBindingsForAddresses({ addresses: ["0x000000000000000000000000000000000000099a"], checkoutRoot });
    assert.deepEqual(bindings, {});
  } finally {
    rmSync(checkoutRoot, { recursive: true, force: true });
  }
});

test("enrichRowsWithTreeRelations: adds a consumed-by relation and replaces org with a found binding", () => {
  const checkoutRoot = tempDir("tree-root-");
  const packageDir = join(checkoutRoot, "some-consumer");
  mkdirSync(packageDir, { recursive: true });
  writeFileSync(join(packageDir, "package.json"), JSON.stringify({ name: "@example/some-consumer" }));
  writeFileSync(join(packageDir, "index.mjs"), "export const key = process.env.ENRICH_TEST_KEY;\n");
  const enterpriseDir = join(checkoutRoot, "some-enterprise");
  mkdirSync(enterpriseDir, { recursive: true });
  writeFileSync(join(enterpriseDir, "package.json"), JSON.stringify({ name: "@example/some-enterprise", account: "0x0000000000000000000000000000000000000AAA" }));
  const row = normalizeWalletRow({
    chain: "base", address: "0x0000000000000000000000000000000000000AAA", owner: "org", role: "auxiliary", relations: [],
    custody: { kind: "env-on-host", host: "bare-cedar-fog", locator: "ENRICH_TEST_KEY" }, balanceReader: null, label: null,
    sources: [{ kind: "env-private-key", locator: "ENRICH_TEST_KEY" }], lastSeen: "2026-09-05T00:00:00Z",
  });
  try {
    const [enriched] = enrichRowsWithTreeRelations({ rows: [row], checkoutRoot });
    assert.equal(enriched.owner, "enterprise:@example/some-enterprise");
    assert.deepEqual(enriched.relations, [{ kind: "consumed-by", target: "@example/some-consumer" }]);
  } finally {
    rmSync(checkoutRoot, { recursive: true, force: true });
  }
});

test("carrierRowsFromFacts: checksums addresses and never introduces an id", () => {
  const rows = carrierRowsFromFacts({
    hiveAccounts: [{ account: "emsenn0", owner: "founder", role: "treasury", custody: { kind: "unknown", host: null, locator: null }, source: "note.md" }],
    baseWallets: [{ address: "0x0000000000000000000000000000000000000abc", owner: "founder", role: "treasury", source: "note.md" }],
    derivedAt: "2026-09-05T00:00:00Z",
  });
  assert.equal(rows.length, 2);
  assert.ok(rows.every((row) => row.id === undefined));
  assert.match(rows[1].address, /^0x[0-9a-fA-F]{40}$/u);
});

test("mergeHostReadouts: a wallet known on two hosts carries two custody entries", () => {
  const rowOnA = { chain: "base", address: "0x0000000000000000000000000000000000000BBB", owner: "org", role: "auxiliary", relations: [], custody: { kind: "keystore-file", host: "bare-cedar-fog", locator: "/a/x.json" }, balanceReader: null, label: null, sources: [{ kind: "keystore-file", locator: "/a/x.json" }], lastSeen: "2026-09-05T00:00:00Z" };
  const rowOnB = { chain: "base", address: "0x0000000000000000000000000000000000000BBB", owner: "org", role: "auxiliary", relations: [], custody: { kind: "keystore-file", host: "cold-red-gate", locator: "/b/x.json" }, balanceReader: null, label: null, sources: [{ kind: "keystore-file", locator: "/b/x.json" }], lastSeen: "2026-09-05T00:00:00Z" };
  const primary = { type: "WalletRegistry", version: 1, derivedAt: "2026-09-05T00:00:00Z", wallets: [rowOnA] };
  const secondary = { type: "WalletRegistry", version: 1, derivedAt: "2026-09-05T00:00:00Z", wallets: [rowOnB] };
  const merged = mergeHostReadouts({ primary, secondary, derivedAt: "2026-09-05T00:00:00Z" });
  assert.equal(merged.wallets.length, 1);
  assert.equal(merged.wallets[0].custodies.length, 2);
  assert.deepEqual(merged.wallets[0].custodies.map((c) => c.host).sort(), ["bare-cedar-fog", "cold-red-gate"]);
});

test("findRepoRoot: resolves a Git worktree without a Guix sentinel", () => {
  const root = tempDir("repo-root-");
  const nested = join(root, "a", "b", "c");
  mkdirSync(nested, { recursive: true });
  try {
    execFileSync("git", ["init", "--quiet", root]);
    assert.equal(findRepoRoot(nested), root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
