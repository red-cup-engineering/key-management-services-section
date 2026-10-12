import assert from "node:assert/strict";
import test from "node:test";
import { Interface, Transaction } from "ethers";
import { checkMandateAllows, normalizeMandate } from "../src/mandate.mjs";

const erc20TransferInterface = new Interface(["function transfer(address to, uint256 amount)"]);
const TOKEN = "0x0000000000000000000000000000000000000003";
const POOL = "0x0000000000000000000000000000000000000004";

const evmMandate = {
  chain: "base",
  address: "0x0000000000000000000000000000000000000009",
  allowedContracts: ["0x0000000000000000000000000000000000000002"],
  maxAmountWei: "1000000000000000000",
  expiresAt: "2026-12-31T00:00:00Z",
};

const tokenCeilingMandate = {
  ...evmMandate,
  allowedContracts: [...evmMandate.allowedContracts, TOKEN],
  allowedTokenTransfers: [{ token: TOKEN, maxAmountRaw: "500", recipients: [POOL] }],
};

const hiveMandate = {
  chain: "hive",
  address: "michael561",
  allowedRecipients: ["sigmund-vexler"],
  maxAmountWei: "5000",
  expiresAt: "2026-12-31T00:00:00Z",
};

test("normalizeMandate accepts a well-formed EVM mandate and lowercases addresses", () => {
  const normalized = normalizeMandate({ ...evmMandate, allowedContracts: ["0x000000000000000000000000000000000000000A"] });
  assert.deepEqual(normalized.allowedContracts, ["0x000000000000000000000000000000000000000a"]);
});

test("normalizeMandate requires allowedContracts for an EVM chain", () => {
  assert.throws(() => normalizeMandate({ ...evmMandate, allowedContracts: undefined }), /allowedContracts must be a nonempty array/u);
});

test("normalizeMandate requires allowedRecipients for a Hive chain", () => {
  assert.throws(() => normalizeMandate({ ...hiveMandate, allowedRecipients: undefined }), /allowedRecipients must be a nonempty array/u);
});

test("normalizeMandate rejects an unsupported chain", () => {
  assert.throws(() => normalizeMandate({ ...evmMandate, chain: "solana" }), /chain solana is not supported/u);
});

test("checkMandateAllows accepts a payload inside every bound", () => {
  const payload = { chain: "base", contract: "0x0000000000000000000000000000000000000002", valueWei: "1" };
  assert.equal(checkMandateAllows({ mandate: evmMandate, payload, now: "2026-09-05T00:00:00Z" }), true);
});

test("checkMandateAllows refuses a contract outside the allowed set", () => {
  const payload = { chain: "base", contract: "0x0000000000000000000000000000000000000099", valueWei: "1" };
  assert.throws(() => checkMandateAllows({ mandate: evmMandate, payload, now: "2026-09-05T00:00:00Z" }), /outside the mandate's allowed set/u);
});

test("checkMandateAllows refuses an amount over the ceiling", () => {
  const payload = { chain: "base", contract: "0x0000000000000000000000000000000000000002", valueWei: "2000000000000000000" };
  assert.throws(() => checkMandateAllows({ mandate: evmMandate, payload, now: "2026-09-05T00:00:00Z" }), /exceeds maxAmountWei/u);
});

test("checkMandateAllows refuses a payload after expiry", () => {
  const payload = { chain: "base", contract: "0x0000000000000000000000000000000000000002", valueWei: "1" };
  assert.throws(() => checkMandateAllows({ mandate: evmMandate, payload, now: "2027-01-01T00:00:00Z" }), /expired at/u);
});

test("checkMandateAllows refuses a chain mismatch", () => {
  const payload = { chain: "ethereum", contract: "0x0000000000000000000000000000000000000002", valueWei: "1" };
  assert.throws(() => checkMandateAllows({ mandate: evmMandate, payload, now: "2026-09-05T00:00:00Z" }), /does not match mandate chain/u);
});

test("checkMandateAllows accepts a Hive payload inside every bound", () => {
  const payload = { chain: "hive", recipient: "sigmund-vexler", amount: "100" };
  assert.equal(checkMandateAllows({ mandate: hiveMandate, payload, now: "2026-09-05T00:00:00Z" }), true);
});

test("checkMandateAllows refuses a Hive recipient outside the allowed set", () => {
  const payload = { chain: "hive", recipient: "someone-else", amount: "100" };
  assert.throws(() => checkMandateAllows({ mandate: hiveMandate, payload, now: "2026-09-05T00:00:00Z" }), /outside the mandate's allowed set/u);
});

test("normalizeMandate accepts and lowercases a well-formed allowedTokenTransfers entry", () => {
  const normalized = normalizeMandate({ ...tokenCeilingMandate, allowedTokenTransfers: [{ token: TOKEN.toUpperCase().replace("0X", "0x"), maxAmountRaw: "500", recipients: [POOL] }] });
  assert.equal(normalized.allowedTokenTransfers[0].token, TOKEN.toLowerCase());
});

test("checkMandateAllows accepts a token transfer within its recipient and amount ceiling", () => {
  const data = erc20TransferInterface.encodeFunctionData("transfer", [POOL, 500n]);
  const payload = { chain: "base", contract: TOKEN, valueWei: "0", transaction: { data } };
  assert.equal(checkMandateAllows({ mandate: tokenCeilingMandate, payload, now: "2026-09-05T00:00:00Z" }), true);
});

test("checkMandateAllows refuses a token transfer over its allowedTokenTransfers ceiling", () => {
  const data = erc20TransferInterface.encodeFunctionData("transfer", [POOL, 501n]);
  const payload = { chain: "base", contract: TOKEN, valueWei: "0", transaction: { data } };
  assert.throws(() => checkMandateAllows({ mandate: tokenCeilingMandate, payload, now: "2026-09-05T00:00:00Z" }), /exceeds maxAmountRaw/u);
});

test("checkMandateAllows refuses a token transfer to a recipient outside allowedTokenTransfers", () => {
  const data = erc20TransferInterface.encodeFunctionData("transfer", ["0x0000000000000000000000000000000000000099", 1n]);
  const payload = { chain: "base", contract: TOKEN, valueWei: "0", transaction: { data } };
  assert.throws(() => checkMandateAllows({ mandate: tokenCeilingMandate, payload, now: "2026-09-05T00:00:00Z" }), /token transfer recipient .* is outside the mandate's allowed set/u);
});

test("checkMandateAllows refuses calldata that does not decode as transfer(address,uint256) for a bounded token", () => {
  const payload = { chain: "base", contract: TOKEN, valueWei: "0", transaction: { data: "0x12345678" } };
  assert.throws(() => checkMandateAllows({ mandate: tokenCeilingMandate, payload, now: "2026-09-05T00:00:00Z" }), /does not decode as transfer/u);
});

test("checkMandateAllows leaves a contract with no allowedTokenTransfers entry unaffected", () => {
  const payload = { chain: "base", contract: "0x0000000000000000000000000000000000000002", valueWei: "1" };
  assert.equal(checkMandateAllows({ mandate: tokenCeilingMandate, payload, now: "2026-09-05T00:00:00Z" }), true);
});

test('transaction-scoped mandates refuse post-admission changes to calldata, nonce and fee envelope',()=>{
 const transaction={chainId:8453,type:2,to:evmMandate.allowedContracts[0],value:'1000',data:'0x1234',nonce:7,gasLimit:'100000',maxFeePerGas:'3000000',maxPriorityFeePerGas:'1000000'};
 const mandate={...evmMandate,unsignedTransactionHash:Transaction.from(transaction).unsignedHash};
 const payload={chain:'base',contract:transaction.to,valueWei:'1000',transaction};
 assert.equal(checkMandateAllows({mandate,payload,now:'2026-10-07T00:00:00Z'}),true);
 for(const patch of [{data:'0x5678'},{nonce:8},{gasLimit:'100001'},{maxFeePerGas:'3000001'},{maxPriorityFeePerGas:'1000001'}]){
  assert.throws(()=>checkMandateAllows({mandate,payload:{...payload,transaction:{...transaction,...patch}},now:'2026-10-07T00:00:00Z'}),/differs from the admitted/);
 }
 assert.throws(()=>normalizeMandate({...mandate,unsignedTransactionHash:'0x12'}),/transaction digest/);
});
