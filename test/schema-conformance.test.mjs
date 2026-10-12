import assert from "node:assert/strict";
import test from "node:test";
import { validateJson } from "@red-cup-engineering/json-schema-services-section/validation";
import walletRegistrySchema from "../schemas/wallet-registry.schema.json" with { type: "json" };
import custodyVerificationSchema from "../schemas/custody-verification.schema.json" with { type: "json" };
import mandateSchema from "../schemas/mandate.schema.json" with { type: "json" };
import createWalletInputSchema from "../schemas/create-wallet.input.schema.json" with { type: "json" };
import createWalletOutputSchema from "../schemas/create-wallet.output.schema.json" with { type: "json" };
import signWithWalletOutputSchema from "../schemas/sign-with-wallet.output.schema.json" with { type: "json" };
import { buildWalletRegistry } from "../src/wallet-registry.mjs";

function assertValid(value, schema, label) {
  const result = validateJson({ value, schema });
  assert.equal(result.valid, true, `${label}: ${JSON.stringify(result.errors)}`);
}

test("wallet-registry schema: a built registry validates, and carries no id field", () => {
  const registry = buildWalletRegistry({
    derivedAt: "2026-09-05T00:00:00Z",
    wallets: [{
      chain: "base", address: "0x0000000000000000000000000000000000000001",
      owner: "org", role: "pool", relations: [{ kind: "consumed-by", target: "pool-service" }],
      custody: { kind: "keystore-file", host: "bare-cedar-fog", locator: "/x.json" }, balanceReader: null,
      label: null, sources: [{ kind: "carrier", locator: "some-note.md" }], lastSeen: "2026-09-05T00:00:00Z",
    }],
  });
  assertValid(registry, walletRegistrySchema, "wallet-registry");
  assert.equal(registry.wallets[0].id, undefined);
});

test("wallet-registry schema: a character-owned, multi-custody row validates", () => {
  const registry = buildWalletRegistry({
    derivedAt: "2026-09-05T00:00:00Z",
    wallets: [{
      chain: "base", address: "0x0000000000000000000000000000000000000002",
      owner: "character:lib/agency/characters/some-character", role: "auxiliary", relations: [],
      custodies: [
        { kind: "env-on-host", host: "bare-cedar-fog", locator: "SOME_KEY", reference: null },
        { kind: "env-on-host", host: "cold-red-gate", locator: "SOME_KEY", reference: null },
      ],
      balanceReader: null, label: { text: "example", source: "some-note.md" },
      sources: [{ kind: "env-private-key", locator: "SOME_KEY" }], lastSeen: "2026-09-05T00:00:00Z",
    }],
  });
  assertValid(registry, walletRegistrySchema, "wallet-registry (multi-custody)");
});

test("custody-verification schema: a result validates", () => {
  assertValid({ type: "CustodyVerification", version: 1, verifiedAt: "2026-09-05T00:00:00Z", counts: { agreed: 1, mismatch: 0, missing: 0 }, rows: [{ chain: "base", address: "0x0000000000000000000000000000000000000001", custodyKind: "keystore-file", host: "bare-cedar-fog", status: "agreed", detail: "ok" }] }, custodyVerificationSchema, "custody-verification");
});

test("mandate schema: an EVM and a Hive mandate both validate", () => {
  assertValid({ chain: "base", address: "0x0000000000000000000000000000000000000009", allowedContracts: ["0x000000000000000000000000000000000000000a"], maxAmountWei: "1", expiresAt: "2026-12-31T00:00:00Z" }, mandateSchema, "evm mandate");
  assertValid({ chain: "hive", address: "michael561", allowedRecipients: ["sigmund-vexler"], maxAmountWei: "1", expiresAt: "2026-12-31T00:00:00Z" }, mandateSchema, "hive mandate");
});

test("create-wallet schemas: request and both result shapes validate", () => {
  assertValid({ id: "x", chain: "base", owner: "org", role: "pool" }, createWalletInputSchema, "input");
  assertValid({ created: false, reason: "KEY_PASSPHRASE is not set in the environment" }, createWalletOutputSchema, "output (refused)");
  assertValid({ created: true, id: "x", chain: "base", address: "0x0000000000000000000000000000000000000001", custody: {}, backup: {}, metaPath: "/x.meta.json", receipt: "ni:///sha-256;abc" }, createWalletOutputSchema, "output (created)");
});

test("sign-with-wallet output schema: both result shapes validate", () => {
  assertValid({ signed: false, reason: "expired" }, signWithWalletOutputSchema, "output (refused)");
  assertValid({ signed: true, id: "x", chain: "base", signature: "0xabc", receipt: "ni:///sha-256;abc" }, signWithWalletOutputSchema, "output (signed)");
});
