#!/usr/bin/env node
/**
 * `key-management-cli` -- the composed face over this section's scripts: `derive`, `create`,
 * `verify`, and `sign`.
 */
import { dirname, resolve } from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { createWallet } from "../scripts/create-wallet.mjs";
import { findEnvFilesToScan, findRepoRoot, readEnvVariablesFromFiles } from "../scripts/derive-set-of-wallets.mjs";
import { signWithWallet } from "../scripts/sign-with-wallet.mjs";
import {
  verifyEnvOnHost, verifyLocalEnvVariable, verifyLocalKeystoreFile, verifyRemoteKeystoreFileExistence, verifyWalletCustody,
} from "../scripts/verify-set-of-wallet-custody.mjs";
import { configRoot } from "../src/keystore-paths.mjs";

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: {
    id: { type: "string" },
    chain: { type: "string" },
    owner: { type: "string" },
    role: { type: "string" },
    "registry-path": { type: "string" },
    registry: { type: "string" },
    mandate: { type: "string" },
    payload: { type: "string" },
    keystore: { type: "string" },
    "journal-root": { type: "string" },
    "checkout-root": { type: "string" },
  },
});

if (import.meta.main) {
  const [command] = positionals;
  switch (command) {
    case "create": {
      const result = await createWallet({
        id: values.id,
        chain: values.chain,
        owner: values.owner,
        role: values.role,
        passphrase: process.env.KEY_PASSPHRASE,
        backupRoot: process.env.KEY_BACKUP_ROOT,
        registryPath: values["registry-path"],
      });
      process.stdout.write(`${JSON.stringify(result)}\n`);
      if (!result.created) process.exitCode = 1;
      break;
    }
    case "verify": {
      const registry = JSON.parse(readFileSync(values.registry, "utf8"));
      const passphrase = process.env.KEY_PASSPHRASE;
      const backupRoot = process.env.KEY_BACKUP_ROOT;
      const checkoutRoot = values["checkout-root"] ?? findRepoRoot(PACKAGE_ROOT);
      const env = { ...readEnvVariablesFromFiles(findEnvFilesToScan({ checkoutRoot, houseConfigRoot: configRoot({ optional: true }) })), ...process.env };
      const result = await verifyWalletCustody({
        registry,
        checkLocalKeystore: (wallet) => verifyLocalKeystoreFile(wallet, { passphrase, backupRoot }),
        checkRemoteKeystore: (wallet) => verifyRemoteKeystoreFileExistence(wallet),
        checkEnvOnHost: (wallet) => verifyEnvOnHost(wallet),
        checkLocalEnv: (wallet) => verifyLocalEnvVariable(wallet, { env }),
      });
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      if (result.counts.mismatch > 0 || result.counts.missing > 0) process.exitCode = 1;
      break;
    }
    case "sign": {
      const result = await signWithWallet({
        id: values.id,
        chain: values.chain,
        mandate: JSON.parse(readFileSync(values.mandate, "utf8")),
        payload: JSON.parse(readFileSync(values.payload, "utf8")),
        keystorePath: values.keystore,
        passphrase: process.env.KEY_PASSPHRASE,
        journalRoot: values["journal-root"],
      });
      process.stdout.write(`${JSON.stringify(result)}\n`);
      if (!result.signed) process.exitCode = 1;
      break;
    }
    default: {
      process.stderr.write("usage: key-management-cli <create|verify|sign> [--id --chain --owner --role --registry-path --registry --mandate --payload --keystore --journal-root]\n" +
        "note: 'derive' runs as node scripts/derive-set-of-wallets.mjs directly (it takes --workspace/--facts/--out, not this CLI's flags).\n");
      process.exitCode = 2;
    }
  }
}
