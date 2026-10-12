/** Chain identity used by wallet custody and signing. Keys remain chain-independent EVM keys. */
export const EVM_CHAIN_IDS = Object.freeze({ ethereum: 1, base: 8453, arbitrum: 42161, avalanche: 43114 });
export const EVM_CHAINS = Object.freeze(Object.keys(EVM_CHAIN_IDS));
export const WALLET_CHAINS = Object.freeze([...EVM_CHAINS, "hive", "hive-engine"]);
export function evmChainId(chain) {
  if (!Object.hasOwn(EVM_CHAIN_IDS, chain)) throw new TypeError(`wallet-chain: ${chain} is not supported`);
  return EVM_CHAIN_IDS[chain];
}
