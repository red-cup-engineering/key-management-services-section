import assert from "node:assert/strict";
import test from "node:test";
import { resolvePaymentReceiver } from "../scripts/resolve-payment-receiver.mjs";

const registry = {
  wallets: [
    { chain: "base", address: "0xAbCdEf0123456789AbCdEf0123456789aBcDeF01" },
    { chain: "hive", address: "emsenn0" },
  ],
};

test("resolves a wallet with an agreed custody entry", () => {
  const custodyVerification = { rows: [{ chain: "base", address: "0xAbCdEf0123456789AbCdEf0123456789aBcDeF01", custodyKind: "env-on-host", status: "agreed" }] };
  const result = resolvePaymentReceiver({ walletId: "base:0xabcdef0123456789abcdef0123456789abcdef01", rail: "base-usdc", registry, custodyVerification });
  assert.deepEqual(result, { walletId: "base:0xabcdef0123456789abcdef0123456789abcdef01", rail: "base-usdc", address: "0xAbCdEf0123456789AbCdEf0123456789aBcDeF01" });
});

test("refuses a wallet whose only custody verified as unknown/missing", () => {
  const custodyVerification = { rows: [{ chain: "hive", address: "emsenn0", custodyKind: "unknown", status: "missing" }] };
  const result = resolvePaymentReceiver({ walletId: "hive:emsenn0", rail: "hive", registry, custodyVerification });
  assert.equal(result.refused, "RECEIVER_NOT_IN_CUSTODY");
  assert.match(result.reason, /no custody entry verified as "agreed"/);
});

test("refuses a rail with no chain-wallet backing", () => {
  const result = resolvePaymentReceiver({ walletId: "hive:emsenn0", rail: "platform", registry, custodyVerification: { rows: [] } });
  assert.equal(result.refused, "RECEIVER_NOT_IN_CUSTODY");
  assert.match(result.reason, /has no chain-wallet backing/);
});

test("refuses a walletId whose chain does not match the rail", () => {
  const result = resolvePaymentReceiver({ walletId: "hive:emsenn0", rail: "base-usdc", registry, custodyVerification: { rows: [] } });
  assert.equal(result.refused, "RECEIVER_NOT_IN_CUSTODY");
  assert.match(result.reason, /does not match rail/);
});

test("refuses a wallet not present in the registry", () => {
  const result = resolvePaymentReceiver({ walletId: "hive:not-a-registered-account", rail: "hive", registry, custodyVerification: { rows: [] } });
  assert.equal(result.refused, "RECEIVER_NOT_IN_CUSTODY");
  assert.match(result.reason, /is not a registered wallet/);
});

test("never returns any field beyond walletId, rail, address", () => {
  const custodyVerification = { rows: [{ chain: "hive", address: "emsenn0", custodyKind: "keystore-file", status: "agreed" }] };
  const result = resolvePaymentReceiver({ walletId: "hive:emsenn0", rail: "hive", registry, custodyVerification });
  assert.deepEqual(Object.keys(result).sort(), ["address", "rail", "walletId"]);
});

test("refuses a malformed walletId", () => {
  const result = resolvePaymentReceiver({ walletId: "not-chain-qualified", rail: "hive", registry, custodyVerification: { rows: [] } });
  assert.equal(result.refused, "RECEIVER_NOT_IN_CUSTODY");
  assert.match(result.reason, /is not a "<chain>:<address>" identity/);
});
