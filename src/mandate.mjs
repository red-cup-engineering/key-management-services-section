import { Interface, Transaction } from "ethers";

import { EVM_CHAINS as EVM_CHAIN_NAMES, evmChainId } from "../data/chains.mjs";
const EVM_CHAINS = new Set(EVM_CHAIN_NAMES);
const HIVE_CHAINS = new Set(["hive", "hive-engine"]);
const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/u;
const HIVE_ACCOUNT_PATTERN = /^[a-z][a-z0-9.-]{2,15}$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/u;
const erc20TransferInterface = new Interface(["function transfer(address to, uint256 amount)"]);

/** @typedef {{chain: ("base"|"ethereum"|"arbitrum"|"avalanche"), contract: string, valueWei: string, transaction?: {data?: string}}} EvmSignPayload */
/** @typedef {{chain: ("hive"|"hive-engine"), recipient: string, amount: string}} HiveSignPayload */
/** @typedef {{token: string, maxAmountRaw: string, recipients: readonly string[]}} AllowedTokenTransfer */
/**
 * @typedef {{chain: ("base"|"ethereum"|"arbitrum"|"avalanche"|"hive"|"hive-engine"), address: string,
 *   allowedContracts: (readonly string[]|undefined), allowedRecipients: (readonly string[]|undefined),
 *   allowedTokenTransfers: (readonly AllowedTokenTransfer[]|undefined),
 *   maxAmountWei: (string|undefined), expiresAt: string}} Mandate
 */

function requireNonEmptyString(value, label) {
  if (typeof value !== "string" || value.length === 0) throw new TypeError(`mandate: ${label} must be a nonempty string`);
  return value;
}

/**
 * Validates and freezes one EVM ERC-20 amount-ceiling entry: the token contract, a maximum raw
 * (smallest-unit) amount, and the recipient set a `transfer` call under this token may pay.
 * Closes the friction route-directed-yield-service filed against this section (`checkMandateAllows`
 * bounded only the allowed-contract set and native `valueWei`, never a token amount).
 * @param {readonly object[]} entries
 * @returns {readonly AllowedTokenTransfer[]}
 * @throws {TypeError} When an entry's token, maxAmountRaw, or recipients is malformed.
 */
function normalizeAllowedTokenTransfers(entries) {
  if (!Array.isArray(entries) || entries.length === 0) throw new TypeError("mandate: allowedTokenTransfers must be a nonempty array");
  return Object.freeze(entries.map((entry) => {
    if (!entry || typeof entry !== "object") throw new TypeError("mandate: allowedTokenTransfers entry must be an object");
    if (!ADDRESS_PATTERN.test(entry.token ?? "")) throw new TypeError(`mandate: allowedTokenTransfers.token ${entry.token} is not an EVM address`);
    if (!DECIMAL_PATTERN.test(entry.maxAmountRaw ?? "")) throw new TypeError("mandate: allowedTokenTransfers.maxAmountRaw must be a nonnegative decimal integer string");
    if (!Array.isArray(entry.recipients) || entry.recipients.length === 0) throw new TypeError("mandate: allowedTokenTransfers.recipients must be a nonempty array");
    const recipients = entry.recipients.map((recipient) => {
      if (!ADDRESS_PATTERN.test(recipient)) throw new TypeError(`mandate: allowedTokenTransfers.recipients entry ${recipient} is not an EVM address`);
      return recipient.toLowerCase();
    });
    return Object.freeze({ token: entry.token.toLowerCase(), maxAmountRaw: entry.maxAmountRaw, recipients: Object.freeze(recipients) });
  }));
}

/**
 * Validates and freezes a bounded signing mandate: one chain, one signer address, an allowed
 * contract set (EVM chains) or allowed recipient set (Hive chains), a maximum amount, and an
 * expiry -- the same bounded-scope shape as Aagaard's per-account envelope check
 * (`aagaard/scripts/cold-red-gate-arbitrage-broadcast.mjs`'s `commonEnvelopeAdmitted`): a
 * fixed account/lane/target combination, never an open-ended signer. The mandate binds an
 * address, per the house ruling that a wallet's identity is its address, never a nickname.
 * @param {object} mandate
 * @returns {Readonly<Mandate>}
 * @throws {TypeError} When the mandate's chain, address, scope, amount, or expiry is malformed.
 */
export function normalizeMandate(mandate) {
  if (!mandate || typeof mandate !== "object") throw new TypeError("mandate: mandate must be an object");
  const chain = mandate.chain;
  requireNonEmptyString(mandate.address, "address");
  const expiresAtMs = Date.parse(mandate.expiresAt ?? "");
  if (!Number.isFinite(expiresAtMs)) throw new TypeError("mandate: expiresAt must be a valid ISO 8601 timestamp");

  if (EVM_CHAINS.has(chain)) {
    if (!ADDRESS_PATTERN.test(mandate.address)) throw new TypeError(`mandate: address ${mandate.address} is not an EVM address`);
    if (!Array.isArray(mandate.allowedContracts) || mandate.allowedContracts.length === 0) {
      throw new TypeError("mandate: allowedContracts must be a nonempty array for an EVM chain");
    }
    if(mandate.unsignedTransactionHash!==undefined&&!/^0x[0-9a-fA-F]{64}$/.test(mandate.unsignedTransactionHash))throw new TypeError('mandate: unsignedTransactionHash must be a transaction digest');
    const allowedContracts = mandate.allowedContracts.map((address) => {
      if (!ADDRESS_PATTERN.test(address)) throw new TypeError(`mandate: allowedContracts entry ${address} is not an EVM address`);
      return address.toLowerCase();
    });
    if (!DECIMAL_PATTERN.test(mandate.maxAmountWei ?? "")) throw new TypeError("mandate: maxAmountWei must be a nonnegative decimal integer string");
    const allowedTokenTransfers = mandate.allowedTokenTransfers === undefined
      ? undefined
      : normalizeAllowedTokenTransfers(mandate.allowedTokenTransfers);
    return Object.freeze({
      chain, address: mandate.address.toLowerCase(), allowedContracts: Object.freeze(allowedContracts),
      ...(mandate.unsignedTransactionHash===undefined?{}:{unsignedTransactionHash:mandate.unsignedTransactionHash.toLowerCase()}),
      allowedRecipients: undefined, allowedTokenTransfers, maxAmountWei: mandate.maxAmountWei, expiresAt: mandate.expiresAt,
    });
  }
  if (HIVE_CHAINS.has(chain)) {
    if (!HIVE_ACCOUNT_PATTERN.test(mandate.address)) throw new TypeError(`mandate: address ${mandate.address} is not a Hive account name`);
    if (!Array.isArray(mandate.allowedRecipients) || mandate.allowedRecipients.length === 0) {
      throw new TypeError("mandate: allowedRecipients must be a nonempty array for a Hive chain");
    }
    for (const account of mandate.allowedRecipients) {
      if (!HIVE_ACCOUNT_PATTERN.test(account)) throw new TypeError(`mandate: allowedRecipients entry ${account} is not a Hive account name`);
    }
    if (!DECIMAL_PATTERN.test(mandate.maxAmountWei ?? "")) throw new TypeError("mandate: maxAmountWei must be a nonnegative decimal integer string of the chain's smallest unit");
    return Object.freeze({
      chain, address: mandate.address, allowedContracts: undefined,
      allowedRecipients: Object.freeze([...mandate.allowedRecipients]), allowedTokenTransfers: undefined,
      maxAmountWei: mandate.maxAmountWei, expiresAt: mandate.expiresAt,
    });
  }
  throw new TypeError(`mandate: chain ${chain} is not supported`);
}

/**
 * Checks whether `contract` is one an `allowedTokenTransfers` entry names, and if so decodes
 * `payload.transaction.data` as `transfer(address,uint256)` and enforces that entry's recipient
 * set and raw-amount ceiling. A contract outside every entry is unaffected -- this is an
 * additional bound layered on top of the allowed-contract check, never a replacement for it.
 * @param {readonly import("./mandate.mjs").AllowedTokenTransfer[]} allowedTokenTransfers
 * @param {string} contract Already-lowercased EVM address.
 * @param {object} payload
 * @throws {TypeError} When the matching entry's calldata does not decode as a transfer, or the
 *   decoded recipient or amount falls outside that entry's bound.
 */
function checkAllowedTokenTransfer(allowedTokenTransfers, contract, payload) {
  const tokenTransfer = allowedTokenTransfers?.find((entry) => entry.token === contract);
  if (!tokenTransfer) return;
  let decoded;
  try {
    decoded = erc20TransferInterface.decodeFunctionData("transfer", payload.transaction?.data ?? "");
  } catch {
    throw new TypeError(`mandate: token transfer calldata for ${contract} does not decode as transfer(address,uint256)`);
  }
  const recipient = decoded[0].toLowerCase();
  const amountRaw = decoded[1].toString();
  if (!tokenTransfer.recipients.includes(recipient)) throw new TypeError(`mandate: token transfer recipient ${recipient} is outside the mandate's allowed set`);
  if (BigInt(amountRaw) > BigInt(tokenTransfer.maxAmountRaw)) throw new TypeError(`mandate: token transfer amount ${amountRaw} exceeds maxAmountRaw ${tokenTransfer.maxAmountRaw}`);
}

/**
 * Checks one sign payload against a normalized mandate: same chain, contract or recipient in
 * the allowed set, amount within the ceiling, an admitted `allowedTokenTransfers` ceiling when
 * one applies to the payload's contract, and mandate not expired at `now`. Throws with a
 * message naming the exact violated bound, so a refusal is a datum rather than a bare boolean.
 * @param {{mandate: object, payload: object, now: string}} input
 * @returns {true}
 * @throws {TypeError} When the payload falls outside the mandate's chain, scope, amount, token
 *   transfer ceiling, or expiry.
 */
export function checkMandateAllows({ mandate, payload, now }) {
  const normalized = normalizeMandate(mandate);
  const nowMs = Date.parse(now ?? "");
  if (!Number.isFinite(nowMs)) throw new TypeError("mandate: now must be a valid ISO 8601 timestamp");
  if (nowMs >= Date.parse(normalized.expiresAt)) throw new TypeError(`mandate: expired at ${normalized.expiresAt}`);
  if (payload?.chain !== normalized.chain) throw new TypeError(`mandate: payload chain ${payload?.chain} does not match mandate chain ${normalized.chain}`);

  if (EVM_CHAINS.has(normalized.chain)) {
    const contract = typeof payload.contract === "string" ? payload.contract.toLowerCase() : payload.contract;
    if (!ADDRESS_PATTERN.test(contract ?? "")) throw new TypeError("mandate: payload contract must be an EVM address");
    if (!normalized.allowedContracts.includes(contract)) throw new TypeError(`mandate: contract ${contract} is outside the mandate's allowed set`);
    if (!DECIMAL_PATTERN.test(payload.valueWei ?? "")) throw new TypeError("mandate: payload valueWei must be a nonnegative decimal integer string");
    if (BigInt(payload.valueWei) > BigInt(normalized.maxAmountWei)) throw new TypeError(`mandate: valueWei ${payload.valueWei} exceeds maxAmountWei ${normalized.maxAmountWei}`);
    if(normalized.unsignedTransactionHash!==undefined){
      const {from,...transaction}=payload.transaction??{};
      const actual=Transaction.from({...transaction,to:contract,value:BigInt(payload.valueWei),chainId:evmChainId(normalized.chain)}).unsignedHash;
      if(actual.toLowerCase()!==normalized.unsignedTransactionHash)throw new TypeError('mandate: transaction differs from the admitted unsigned transaction');
    }
    checkAllowedTokenTransfer(normalized.allowedTokenTransfers, contract, payload);
    return true;
  }

  if (!normalized.allowedRecipients.includes(payload.recipient)) throw new TypeError(`mandate: recipient ${payload.recipient} is outside the mandate's allowed set`);
  if (!DECIMAL_PATTERN.test(payload.amount ?? "")) throw new TypeError("mandate: payload amount must be a nonnegative decimal integer string of the chain's smallest unit");
  if (BigInt(payload.amount) > BigInt(normalized.maxAmountWei)) throw new TypeError(`mandate: amount ${payload.amount} exceeds maxAmountWei ${normalized.maxAmountWei}`);
  return true;
}
