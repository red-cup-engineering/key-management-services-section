import assert from "node:assert/strict";
import test from "node:test";
import { buildWalletRegistry, findWalletRow, findWalletRowsByAddress, mergeWalletObservations, normalizeWalletCustody, normalizeWalletRow } from "../src/wallet-registry.mjs";

const baseRow = {
  chain: "base",
  address: "0x0000000000000000000000000000000000000001",
  owner: "org",
  role: "pool",
  relations: [{ kind: "consumed-by", target: "pool-service" }],
  custody: { kind: "keystore-file", host: "bare-cedar-fog", locator: "/tmp/x.json" },
  balanceReader: "@red-cup-engineering/treasury-observation-service/native",
  lastSeen: "2026-09-05T00:00:00Z",
};

test("normalizeWalletRow accepts a well-formed row and freezes it, carrying no id", () => {
  const row = normalizeWalletRow(baseRow);
  assert.equal(row.address, "0x0000000000000000000000000000000000000001");
  assert.equal(row.id, undefined);
  assert.ok(Object.isFrozen(row));
  assert.ok(Object.isFrozen(row.relations));
  assert.deepEqual(row.custodies, [row.custody]);
});

test("normalizeWalletRow defaults custody to unknown, label to null, sources and relations to empty", () => {
  const row = normalizeWalletRow({ ...baseRow, custody: undefined, relations: undefined });
  assert.deepEqual(row.custody, { kind: "unknown", host: null, locator: null, reference: null, derivationPath: null });
  assert.deepEqual(row.relations, []);
  assert.equal(row.label, null);
  assert.deepEqual(row.sources, []);
});

test("normalizeWalletRow rejects an unsupported chain", () => {
  assert.throws(() => normalizeWalletRow({ ...baseRow, chain: "solana" }), /chain solana is not supported/u);
});

test("normalizeWalletRow rejects a malformed owner", () => {
  assert.throws(() => normalizeWalletRow({ ...baseRow, owner: "someone" }), /owner someone must be org, founder, enterprise/u);
});

test("normalizeWalletRow accepts a character owner", () => {
  const row = normalizeWalletRow({ ...baseRow, owner: "character:lib/agency/characters/some-character" });
  assert.equal(row.owner, "character:lib/agency/characters/some-character");
});

test("normalizeWalletRow rejects an address that does not match its chain's format", () => {
  assert.throws(() => normalizeWalletRow({ ...baseRow, address: "not-an-address" }), /is not a valid base address/u);
  assert.throws(() => normalizeWalletRow({ ...baseRow, chain: "hive", address: "0x0000000000000000000000000000000000000001" }), /is not a valid hive address/u);
});

test("normalizeWalletRow rejects an unsupported role", () => {
  assert.throws(() => normalizeWalletRow({ ...baseRow, role: "whale" }), /role whale is not supported/u);
});

test("normalizeWalletCustody rejects a non-unknown kind missing host/locator", () => {
  assert.throws(() => normalizeWalletCustody({ kind: "keystore-file" }), /custody.host must be a nonempty string/u);
});

test("normalizeWalletCustody rejects unknown kind carrying a host", () => {
  assert.throws(() => normalizeWalletCustody({ kind: "unknown", host: "cold-red-gate", locator: null }), /unknown custody must not name a host/u);
});

test("normalizeWalletCustody accepts unknown kind carrying a public reference", () => {
  const custody = normalizeWalletCustody({ kind: "unknown", host: null, locator: null, reference: "SOME_ENV_VAR" });
  assert.equal(custody.reference, "SOME_ENV_VAR");
});

test("buildWalletRegistry sorts by chain then address and rejects duplicate identity", () => {
  const registry = buildWalletRegistry({
    derivedAt: "2026-09-05T00:00:00Z",
    wallets: [
      { ...baseRow, address: "0x0000000000000000000000000000000000000099" },
      { ...baseRow, chain: "hive", address: "aaa-wallet" },
    ],
  });
  assert.equal(registry.wallets[0].chain, "base");
  assert.equal(registry.wallets[1].chain, "hive");
  assert.throws(() => buildWalletRegistry({ derivedAt: "x", wallets: [baseRow, baseRow] }), /duplicate wallet identity/u);
});

test("findWalletRow finds the one row matching {chain, address}", () => {
  const registry = buildWalletRegistry({ derivedAt: "2026-09-05T00:00:00Z", wallets: [baseRow] });
  assert.ok(findWalletRow(registry, { chain: "base", address: baseRow.address }));
  assert.equal(findWalletRow(registry, { chain: "hive", address: baseRow.address }), undefined);
});

test("findWalletRowsByAddress returns every match across chains", () => {
  const registry = buildWalletRegistry({ derivedAt: "2026-09-05T00:00:00Z", wallets: [baseRow, { ...baseRow, chain: "ethereum" }] });
  assert.equal(findWalletRowsByAddress(registry, baseRow.address).length, 2);
});

test("mergeWalletObservations folds two observations of the same identity into one row", () => {
  const observationOne = normalizeWalletRow({ ...baseRow, custody: { kind: "unknown", host: null, locator: null }, sources: [{ kind: "carrier", locator: "note.md" }] });
  const observationTwo = normalizeWalletRow({ ...baseRow, owner: "enterprise:aagaard", custody: { kind: "env-on-host", host: "cold-red-gate", locator: "SOME_KEY" }, sources: [{ kind: "env-private-key", locator: "SOME_KEY" }] });
  const merged = mergeWalletObservations([observationOne, observationTwo]);
  assert.equal(merged.length, 1);
  assert.equal(merged[0].owner, "enterprise:aagaard");
  assert.equal(merged[0].custodies.length, 2);
  assert.equal(merged[0].sources.length, 2);
});

test("mergeWalletObservations leaves distinct identities as separate rows", () => {
  const merged = mergeWalletObservations([normalizeWalletRow(baseRow), normalizeWalletRow({ ...baseRow, chain: "hive", address: "some-account" })]);
  assert.equal(merged.length, 2);
});
