#!/usr/bin/env node
// hive-key — Hive role keys in the key store: set one, derive them from a master password
// (verified against on-chain authorities), report which roles are stored, check stored keys
// against the chain, and identify or sort loose key material into the store.
import { PrivateKey } from "@red-cup-engineering/hive-blockchain-client-service/keys.mjs";
import { RpcClient } from "@red-cup-engineering/hive-blockchain-client-service/rpc.mjs";
import { setHiveKey, loadHiveKey, hiveKeyStatus, KEY_ROLES } from "../src/hive-keystore.mjs";
import { identifyKeys, sortDump } from "./sort-hive-key-vault.mjs";
const argv = process.argv.slice(2);
const out = (v)=>console.log(typeof v === "string" ? v : JSON.stringify(v, null, 2));
const die = (msg)=>{
    console.error(`hive-key: ${msg}`);
    process.exit(1);
};
const env = process.env;
const root = env["HIVE_KEY_ROOT"] || undefined;
function nodesFrom(flagNode) {
    if (flagNode) return [
        flagNode
    ];
    if (env["HIVE_NODES"]) return env["HIVE_NODES"].split(",").map((s)=>s.trim()).filter(Boolean);
    return undefined;
}
function takeFlag(args, flag) {
    const i = args.indexOf(flag);
    if (i === -1) return {
        value: undefined,
        rest: args
    };
    const value = args[i + 1];
    return {
        value,
        rest: [
            ...args.slice(0, i),
            ...args.slice(i + 2)
        ]
    };
}
function hasFlag(args, flag) {
    const i = args.indexOf(flag);
    if (i === -1) return {
        present: false,
        rest: args
    };
    return {
        present: true,
        rest: [
            ...args.slice(0, i),
            ...args.slice(i + 1)
        ]
    };
}
function takeEqFlag(args, flag) {
    const i = args.findIndex((a)=>a.startsWith(`${flag}=`));
    if (i !== -1) return {
        value: args[i].slice(flag.length + 1),
        rest: [
            ...args.slice(0, i),
            ...args.slice(i + 1)
        ]
    };
    return takeFlag(args, flag);
}
async function readStdin() {
    const chunks = [];
    for await (const c of process.stdin)chunks.push(c);
    return Buffer.concat(chunks).toString("utf8");
}
function isRole(s) {
    return KEY_ROLES.includes(s);
}
async function cmdKeySet(args) {
    const { present: encrypt, rest: r1 } = hasFlag(args, "--encrypt");
    const { present: passStdin, rest: rest } = hasFlag(r1, "--passphrase-stdin");
    const [account, role] = rest;
    if (!account || !role) return die("set <account> <role> [--encrypt] [--passphrase-stdin]");
    if (!isRole(role)) return die(`unknown role ${role}; expected one of ${KEY_ROLES.join(", ")}`);
    const stdin = await readStdin();
    const lines = stdin.split("\n");
    const wif = (lines[0] ?? "").trim();
    if (!wif) return die("no WIF on stdin (line 1)");
    if (encrypt) {
        if (!passStdin) return die("--encrypt requires --passphrase-stdin (passphrase on stdin line 2)");
        const passphrase = (lines[1] ?? "").replace(/\n$/, "");
        if (!passphrase) return die("no passphrase on stdin (line 2)");
        await setHiveKey(account, role, wif, {
            passphrase,
            ...root !== undefined ? {
                root
            } : {}
        });
        out(`stored sealed ${role} key for @${account}`);
        return 0;
    }
    await setHiveKey(account, role, wif, {
        ...root !== undefined ? {
            root
        } : {}
    });
    out(`stored plaintext ${role} key for @${account}`);
    return 0;
}
async function cmdKeyDerive(args) {
    const { deriveRoleKey } = await import("@red-cup-engineering/hive-blockchain-client-service/keys.mjs");
    const { HiveClient } = await import("@red-cup-engineering/hive-blockchain-client-service");
    const { present: encrypt, rest: r1 } = hasFlag(args, "--encrypt");
    const { present: passStdin, rest: r2 } = hasFlag(r1, "--passphrase-stdin");
    const { present: noVerify, rest: r3 } = hasFlag(r2, "--no-verify");
    const { present: force, rest: r4 } = hasFlag(r3, "--force");
    const { value: node, rest: r5 } = takeFlag(r4, "--node");
    const { value: saveRaw, rest } = takeEqFlag(r5, "--save");
    const account = rest[0];
    if (!account) return die("derive <account> --save=active,posting [--encrypt --passphrase-stdin] [--no-verify] [--force]\n  master password on stdin line 1 (consumed, never stored); encryption passphrase on line 2 with --encrypt");
    const roles = [];
    for (const r of (saveRaw ?? "active,posting,memo").split(",").map((s)=>s.trim()).filter(Boolean)){
        if (!isRole(r)) return die(`unknown role ${r}; expected from ${KEY_ROLES.join(", ")}`);
        roles.push(r);
    }
    if (roles.includes("owner") && !force) {
        return die("refusing to store the OWNER key operationally — it controls the whole account; keep it cold. Re-run with --force if you truly mean to.");
    }
    const stdin = await readStdin();
    const lines = stdin.split("\n");
    const password = (lines[0] ?? "").trim();
    if (!password) return die("no master password on stdin (line 1)");
    if (encrypt && !passStdin) return die("--encrypt requires --passphrase-stdin (encryption passphrase on stdin line 2)");
    const passphrase = encrypt ? (lines[1] ?? "").replace(/\n$/, "") : "";
    if (encrypt && !passphrase) return die("no encryption passphrase on stdin (line 2)");
    let roleKeys;
    if (!noVerify) {
        const nodes = nodesFrom(node);
        const client = new HiveClient({
            ...nodes !== undefined ? {
                nodes
            } : {}
        });
        const auth = await client.getAccountAuthorities([
            account
        ]);
        roleKeys = auth.get(account);
        if (!roleKeys && !force) return die(`@${account} not found on chain; use --no-verify to skip the check or --force to store anyway`);
    }
    let stored = 0;
    for (const role of roles){
        const priv = deriveRoleKey(account, role, password);
        const pub = priv.createPublic().toString();
        if (roleKeys) {
            if (roleKeys.get(pub) !== role) {
                if (!force) {
                    out(`SKIP ${role}: derived key ${pub} is not @${account}'s on-chain ${role} authority (wrong master password, or keys rotated)`);
                    continue;
                }
                out(`WARNING ${role}: derived key does not match the chain; storing anyway (--force)`);
            } else {
                out(`verified ${role}: matches @${account}'s on-chain authority`);
            }
        }
        try {
            await setHiveKey(account, role, priv.toString(), {
                ...encrypt ? {
                    passphrase
                } : {},
                ...root !== undefined ? {
                    root
                } : {}
            });
            out(`stored ${encrypt ? "sealed" : "plaintext"} ${role} key for @${account} (${pub})`);
            stored += 1;
        } catch (error) {
            out(`SKIP ${role}: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
    out("");
    out(`done: ${stored}/${roles.length} role key(s) stored. The master password was used to derive and was NOT saved — keep it off this box.`);
    return stored > 0 ? 0 : 1;
}
function cmdKeyStatus(args) {
    const account = args[0];
    if (!account) return die("status <account>");
    const status = hiveKeyStatus(account, root);
    out(`@${account} key coverage:`);
    for (const role of KEY_ROLES)out(`  ${role}: ${status[role]}`);
    return 0;
}
async function cmdKeyCheck(args) {
    const { deriveRoleKey } = await import("@red-cup-engineering/hive-blockchain-client-service/keys.mjs");
    const { HiveClient } = await import("@red-cup-engineering/hive-blockchain-client-service");
    const { value: node, rest: r1 } = takeFlag(args, "--node");
    const { present: passStdin, rest } = hasFlag(r1, "--passphrase-stdin");
    const account = rest[0];
    if (!account) return die("check <account> [--node URL] [--passphrase-stdin]");
    const status = hiveKeyStatus(account, root);
    const present = KEY_ROLES.filter((r)=>status[r] !== "absent");
    if (present.length === 0) {
        out(`@${account}: no stored keys`);
        return 1;
    }
    const passphrase = passStdin ? (await readStdin()).split("\n")[0]?.trim() : undefined;
    const nodes = nodesFrom(node);
    const client = new HiveClient({
        ...nodes !== undefined ? {
            nodes
        } : {}
    });
    const roleKeys = (await client.getAccountAuthorities([
        account
    ])).get(account);
    out(`@${account} key check:`);
    let mismatches = 0;
    for (const role of present){
        if (status[role] === "sealed" && passphrase === undefined) {
            out(`  ${role}: sealed — pass --passphrase-stdin to verify`);
            continue;
        }
        let pub;
        try {
            const wif = loadHiveKey(account, role, {
                ...passphrase !== undefined ? {
                    passphrase
                } : {},
                ...root !== undefined ? {
                    root
                } : {}
            });
            if (!wif) throw new Error(`no ${role} key stored`);
            pub = PrivateKey.from(wif).createPublic().toString();
        } catch (error) {
            out(`  ${role}: cannot load (${error instanceof Error ? error.message : String(error)})`);
            continue;
        }
        if (!roleKeys) {
            out(`  ${role}: ${pub} — @${account} not found on chain`);
            continue;
        }
        const chainRole = roleKeys.get(pub);
        if (chainRole === role) {
            out(`  ${role}: ✓ matches @${account}'s on-chain ${role} authority`);
        } else {
            mismatches += 1;
            out(`  ${role}: ✗ MISMATCH — stored key ${pub} is ${chainRole ? `the ${chainRole} key` : "not an authority"} of @${account}`);
        }
    }
    return mismatches > 0 ? 2 : 0;
}
async function main() {
    const cmd = argv[0];
    const rest = argv.slice(1);
    const accountsFlag = (args)=>(takeFlag(args, "--accounts").value ?? "").split(",").map((a)=>a.trim()).filter(Boolean);
    switch(cmd){
        case "set": return cmdKeySet(rest);
        case "derive": return cmdKeyDerive(rest);
        case "status": return cmdKeyStatus(rest);
        case "check": return cmdKeyCheck(rest);
        case "identify": return identifyKeys({ rpc: new RpcClient(), accounts: accountsFlag(rest), ...root !== undefined ? { vaultDir: root } : {} });
        case "sort":
            if (!rest[0]) return die("sort <dump-file> [--accounts a,b] [--write]");
            return sortDump({ rpc: new RpcClient(), dump: rest[0], accounts: accountsFlag(rest), write: rest.includes("--write"), ...root !== undefined ? { vaultDir: root } : {} });
        default:
            console.error("usage: hive-key <set|derive|status|check|identify|sort> ...");
            console.error("  hive-key set <account> <role> [--encrypt] [--passphrase-stdin]");
            console.error("  hive-key derive <account> --save=active,posting [--encrypt --passphrase-stdin]");
            console.error("  hive-key status <account>");
            console.error("  hive-key check <account> [--passphrase-stdin]");
            console.error("  hive-key identify [--accounts a,b]");
            console.error("  hive-key sort <dump-file> [--accounts a,b] [--write]");
            console.error("  HIVE_KEY_ROOT overrides the key store root (hive/ in CREDENTIALS_DIRECTORY); HIVE_NODES the RPC nodes.");
            return 1;
    }
}
main().then((code)=>{
    process.exitCode = code;
}).catch((err)=>{
    console.error(`hive-key: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
});
