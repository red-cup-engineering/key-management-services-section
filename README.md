# Key Management Services Section

Key custody for the 561 Group's own wallets, spanning the `ethereum-services-section` (Base,
Ethereum, Arbitrum, Avalanche) and `hive-services-section` (Hive, Hive-Engine) custody the tree already has, without
copying either one's crypto: EVM keys are standard Ethereum keystore v3 JSON (`ethers`); Hive
keys are the WIF format `hive-blockchain-client-service` already defines.

## What this section owns

- `data/chains.mjs` — the shared EVM chain identity used in registry validation, key paths, mandates, and signing.
- `src/wallet-registry.mjs` — the `WalletRegistry` algebra: a row's shape (`chain`,
  `address`, `owner`, `role`, `relations`, `custody`, `balanceReader`, `lastSeen`), validation,
  and assembly. Unknown custody is recorded as `unknown`, never guessed.
- `src/mandate.mjs` — a bounded signing mandate (one chain, one wallet address, an allowed contract
  or recipient set, a maximum amount, an expiry) and the check a payload must pass before it is
  signed. The shape mirrors Aagaard's own per-account envelope check
  (`hive-services-section/services/aagaard/scripts/cold-red-gate-arbitrage-broadcast.mjs`).
- `src/keystore-paths.mjs` — the canonical config-root and key-file path builders:
  `~/.config/561-group/keys/<chain>/<id>.<json|wif>`, matching the
  `~/.config/561-group/ops-mcp-client.env` convention already in use.
- `scripts/derive-set-of-wallets.mjs` — derives the `WalletRegistry`, never hand-written: folds
  the `ethereum-services-section` enterprise-wallet census (run as a subprocess, since that
  script is not part of that package's export map) with the Hive accounts and Base wallets named
  in house carriers (`data/records/wallet-facts-source-records/2026-09-05-wallet-facts-source.json`, each row citing its
  carrier).
- `scripts/create-wallet.mjs` — generates one new key, writes it under the config root and a
  second copy under a separately named backup root, verifies both decrypt/parse back to the same
  address, and appends the row to a registry when one is named. Refuses, as data, when
  `KEY_PASSPHRASE` or `KEY_BACKUP_ROOT` is not set in the environment, or when the id is already
  registered — it never invents either value.
- `scripts/verify-set-of-wallet-custody.mjs` — checks every registry row's custody: a
  `keystore-file` row's files exist, are mode `0600`, and decrypt/parse to the registered
  address (locally) or exist at that mode (remotely, without ever reading the key back to this
  host); an `env-on-host` row is checked only for the named variable's presence, never its
  value.
- `scripts/sign-with-wallet.mjs` — loads a key, checks the payload against a mandate, and signs.
  The caller never sees the private key; a payload outside the mandate is refused as data.
- `scripts/resolve-payment-receiver.mjs` — resolves a payment rail's receiver address from the
  `WalletRegistry`, given only `{walletId, rail}` (`walletId` is `"<chain>:<address>"`, never a
  nickname or character name). Returns `{walletId, rail, address}` only when the registry holds
  the wallet for that rail's chain AND `verify-set-of-wallet-custody` verifies at least one of
  its custody entries as `"agreed"`; otherwise returns the refusal datum
  `{refused: "RECEIVER_NOT_IN_CUSTODY", walletId, rail, reason}`. This is the mechanical fix for
  the 2026-09-05 ruling (payment-receivers-are-parameters-never-literals): a caller can only ever
  hold a `walletId` parameter, never a literal receiver, so a wallet the Group holds no verified
  key for cannot be routed a payment.
- `scripts/check-set-of-hardcoded-payment-receivers.mjs` — scans a directory or file list for
  literal payment-receiver values (EVM `0x` addresses, Lightning addresses, LNURLs, Hive account
  names) sitting in a receiver-shaped field (`receiver`, `payTo`, `to`, `address`, `account`,
  `lnurl`, `X402_PAY_TO`) across `.mjs`/`.mts`/`.json`/`.jsonc`/`.toml`/`.html`/`.md` files, and
  exits 1 when it finds any. The only exclusions are this section's own derived storage
  (`data/records/`) and its own test fixtures (`test/fixtures/`) -- the documented allowlist.
- `apps/key-management-cli.mjs` — the composed CLI face (`create`, `verify`, `sign`; `derive`
  runs directly as `node scripts/derive-set-of-wallets.mjs`, since it takes different flags).

## Absolute rules this section holds itself to

- Never reads, prints, copies, or moves `.env*`, `*.wif`, or any existing private key.
- Every secret file this section writes is written outside the git tree, under
  `~/.config/561-group/keys/<chain>/<id>.<ext>`, mode `0600`, with a second copy under
  `$KEY_BACKUP_ROOT`. A passphrase is read from `KEY_PASSPHRASE` in the runtime environment at
  call time — never baked into a file or passed as a stored default.
- A `create-wallet` or `sign-with-wallet` call missing `KEY_PASSPHRASE`/`KEY_BACKUP_ROOT`
  refuses with a datum naming the missing variable; it never invents one.

## Tests

`npm test` runs the keystore round trip against a temporary `HOME` and a temporary backup root
(via `mkdtempSync`), never the real ones.

EVM mandates may bind `unsignedTransactionHash`, which the shared signer checks
against the exact unsigned transaction alongside chain, destination, value, expiry,
and signer address. JSON schemas admit the same Base, Ethereum, Arbitrum, Avalanche,
Hive, and Hive-Engine chain vocabulary as `data/chains.mjs`, including the existing
ERC-20 recipient and raw-amount ceiling.
