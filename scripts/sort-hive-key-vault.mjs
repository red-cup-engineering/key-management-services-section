// sort-hive-key-vault — the hive-key CLI's identify and sort: sort a pile of Hive key material into the key store and report which
// account role each line unlocks, matching every derived public key against on-chain
// authorities. Vault lines live in <root>/<account>/*.txt beside the role .wif files; secrets are
// identified by file and line number only, never printed.
import { readFileSync, readdirSync, statSync, mkdirSync, appendFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import path from "node:path";
import { RpcClient } from "@red-cup-engineering/hive-blockchain-client-service/rpc.mjs";
import { KEY_ROLES, classifyKeyMaterial, deriveRoleKey } from "@red-cup-engineering/hive-blockchain-client-service/keys.mjs";
import { getAccountAuthorities, getKeyReferences } from "@red-cup-engineering/hive-blockchain-client-service/chain.mjs";
import { defaultHiveKeyRoot } from "../src/hive-keystore.mjs";

export function readVault(vaultDir) {
    const entries = [];
    let accountDirs = [];
    try {
        accountDirs = readdirSync(vaultDir).filter((d) => statSync(path.join(vaultDir, d)).isDirectory());
    }
    catch {
        return { accounts: [], entries };
    }
    for (const account of accountDirs) {
        const dir = path.join(vaultDir, account);
        for (const file of readdirSync(dir).filter((f) => f.endsWith(".txt"))) {
            const lines = readFileSync(path.join(dir, file), "utf8").split("\n");
            lines.forEach((raw, i) => {
                const line = raw.trim();
                if (line === "" || line.startsWith("#"))
                    return;
                entries.push({ account, file: path.join(account, file), lineNo: i + 1, line });
            });
        }
    }
    return { accounts: accountDirs, entries };
}
/** Account directories in the vault, excluding holding pens like `_unsorted`. */
export function vaultAccounts(vaultDir) {
    try {
        return readdirSync(vaultDir).filter((d) => !d.startsWith("_") && statSync(path.join(vaultDir, d)).isDirectory());
    }
    catch {
        return [];
    }
}
/**
 * Sort a pile of Hive key material into "what is it and which account/role
 * does it unlock," printing only public facts. Every derived/parsed public
 * key is matched against the ON-CHAIN authorities of EVERY account in the
 * vault (not just its own directory — misfiled keys are the whole problem
 * being solved). Master-password candidates are tried against every vault
 * account too. Returns a process exit code.
 */
export async function identifyKeys(options) {
    const { rpc, vaultDir = defaultHiveKeyRoot(), accounts: extra = [], log = console.log, error = console.error, } = options;
    const { accounts: dirAccounts, entries } = readVault(vaultDir);
    const accounts = [...new Set([...dirAccounts, ...extra])];
    if (accounts.length === 0) {
        error(`no account directories under ${vaultDir} and no --accounts given`);
        return 1;
    }
    if (entries.length === 0) {
        error(`no key lines found under ${vaultDir}/<account>/*.txt`);
        return 1;
    }
    log(`vault: ${vaultDir}`);
    log(`accounts: ${accounts.join(", ")}`);
    const authorities = await getAccountAuthorities(rpc, accounts);
    for (const name of accounts) {
        if (!authorities.has(name))
            log(`  WARNING: @${name} does not exist on chain (typo in directory name?)`);
    }
    // pubkey -> [{account, role}] across the whole vault
    const lookup = new Map();
    for (const [name, roleKeys] of authorities) {
        for (const [key, role] of roleKeys) {
            if (!lookup.has(key))
                lookup.set(key, []);
            lookup.get(key).push({ account: name, role });
        }
    }
    const held = new Map(accounts.map((a) => [a, new Map()])); // account -> role -> source desc
    const note = (acct, role, src, kind) => {
        const roles = held.get(acct);
        if (roles && !roles.has(role))
            roles.set(role, `${src} (${kind})`);
    };
    log("\n--- lines ---");
    for (const entry of entries) {
        const src = `${entry.file}:${entry.lineNo}`;
        const c = classifyKeyMaterial(entry.line);
        if (c.kind === "malformed-public-key" || c.kind === "malformed-wif") {
            log(`${src}  ${c.kind}: ${c.problem}`);
            continue;
        }
        if (c.kind === "public-key" || c.kind === "private-key") {
            const matches = lookup.get(c.pubkey) ?? [];
            const where = matches.length > 0
                ? matches.map((m) => `@${m.account} ${m.role.toUpperCase()}`).join(", ")
                : "no match among vault accounts";
            log(`${src}  ${c.kind} → ${c.pubkey}`);
            log(`        ${where}`);
            if (c.kind === "private-key")
                for (const m of matches)
                    note(m.account, m.role, src, "wif");
            continue;
        }
        // password candidate: try as master password for every vault account
        const hits = [];
        for (const name of accounts) {
            for (const role of KEY_ROLES) {
                try {
                    const pub = deriveRoleKey(name, role, entry.line).createPublic().toString();
                    for (const m of lookup.get(pub) ?? []) {
                        hits.push(`@${m.account} ${m.role.toUpperCase()} (derived as ${name}/${role})`);
                        note(m.account, m.role, src, "master password");
                    }
                }
                catch { /* derived scalar out of range: not this password */ }
            }
        }
        log(`${src}  password-candidate`);
        log(`        ${hits.length > 0 ? hits.join(", ") : "derives no key matching any vault account"}`);
    }
    log("\n--- coverage ---");
    for (const name of accounts) {
        if (!authorities.has(name))
            continue;
        const roles = held.get(name);
        log(`@${name}`);
        for (const r of KEY_ROLES)
            log(`    ${roles.has(r) ? `${r} ✓ ${roles.get(r)}` : `${r} ✗`}`);
    }
    return 0;
}
/**
 * Take ONE file with all your Hive key material dumped in it (one item per
 * line) and sort it into the vault. WIF/STM lines are reverse-looked-up on
 * chain (account_by_key_api.get_key_references) — no hints needed; master
 * passwords are tried against every @hint, vault directory, and `accounts`
 * entry. An unverifiable line under an @hint still files to that account
 * (marked unverified); lines attributable nowhere go to `_unsorted`.
 * Appends dedupe against lines already in the vault. DRY RUN unless
 * `write`. After a successful write, DELETE THE DUMP (shred -u <file>).
 * Returns a process exit code.
 */
export async function sortDump(options) {
    const { rpc, dump, vaultDir = defaultHiveKeyRoot(), accounts: extra = [], write = false, log = console.log, error = console.error, } = options;
    // ---- parse the dump: items + @context hints ----
    const items = [];
    const hinted = new Set();
    let context = null;
    readFileSync(dump, "utf8").split("\n").forEach((raw, i) => {
        const line = raw.trim();
        if (line === "" || line.startsWith("#"))
            return;
        if (/^@[a-z0-9.-]{3,16}$/.test(line)) {
            context = line.slice(1);
            hinted.add(context);
            return;
        }
        items.push({ lineNo: i + 1, line, context, ...classifyKeyMaterial(line) });
    });
    if (items.length === 0) {
        error("dump contains no key lines");
        return 1;
    }
    const candidates = [...new Set([...hinted, ...vaultAccounts(vaultDir), ...extra])];
    // ---- derive every public key we can, then one reverse lookup ----
    const passwordDerivations = new Map();
    for (const item of items) {
        if (item.kind !== "password-candidate")
            continue;
        const derived = [];
        for (const account of candidates) {
            for (const role of KEY_ROLES) {
                try {
                    derived.push({ account, role, pubkey: deriveRoleKey(account, role, item.line).createPublic().toString() });
                }
                catch { /* out-of-range scalar: skip */ }
            }
        }
        passwordDerivations.set(item, derived);
    }
    const allPubkeys = [...new Set([
            ...items.flatMap((it) => (it.kind === "public-key" || it.kind === "private-key" ? [it.pubkey] : [])),
            ...[...passwordDerivations.values()].flat().map((d) => d.pubkey),
        ])];
    const references = new Map();
    if (allPubkeys.length > 0) {
        const refs = await getKeyReferences(rpc, allPubkeys);
        allPubkeys.forEach((key, i) => references.set(key, refs[i] ?? []));
    }
    // Role naming needs full authorities; candidates are fetched too because
    // the reverse index covers owner/active/posting but NOT memo keys.
    const referencedAccounts = [...new Set([...references.values()].flat())];
    const fetchNames = [...new Set([...referencedAccounts, ...candidates])];
    const authorities = fetchNames.length > 0 ? await getAccountAuthorities(rpc, fetchNames) : new Map();
    const roleOf = (account, pubkey) => authorities.get(account)?.get(pubkey) ?? "unknown-role";
    const ownersOf = (pubkey) => [...new Set([
            ...(references.get(pubkey) ?? []),
            ...[...authorities.entries()].filter(([, keys]) => keys.has(pubkey)).map(([name]) => name),
        ])];
    // ---- attribute ----
    const plan = [];
    for (const item of items) {
        if (item.kind === "malformed-public-key" || item.kind === "malformed-wif") {
            plan.push({ item, account: "_unsorted", label: `${item.kind}: ${item.problem}`, verified: false });
            continue;
        }
        if (item.kind === "public-key" || item.kind === "private-key") {
            const owners = ownersOf(item.pubkey);
            if (owners.length > 0) {
                for (const account of owners) {
                    plan.push({ item, account, label: `${item.kind} → ${item.pubkey} = ${roleOf(account, item.pubkey).toUpperCase()}`, verified: true });
                }
            }
            else if (item.context) {
                plan.push({ item, account: item.context, label: `${item.kind} → ${item.pubkey} — no chain reference; filed by @hint, UNVERIFIED`, verified: false });
            }
            else {
                plan.push({ item, account: "_unsorted", label: `${item.kind} → ${item.pubkey} — no chain reference, no @hint`, verified: false });
            }
            continue;
        }
        // password candidate
        const hits = (passwordDerivations.get(item) ?? []).filter((d) => ownersOf(d.pubkey).includes(d.account));
        if (hits.length > 0) {
            const accounts = [...new Set(hits.map((h) => h.account))];
            for (const account of accounts) {
                const roles = hits.filter((h) => h.account === account).map((h) => h.role.toUpperCase()).join("+");
                plan.push({ item, account, label: `master password → ${roles}`, verified: true });
            }
        }
        else if (item.context) {
            plan.push({ item, account: item.context, label: "password — derives nothing on chain for any candidate; filed by @hint, UNVERIFIED", verified: false });
        }
        else {
            plan.push({ item, account: "_unsorted", label: "password — derives nothing on chain for any candidate, no @hint", verified: false });
        }
    }
    // ---- report / write ----
    log(`${write ? "writing" : "DRY RUN (use --write to apply)"} — vault: ${vaultDir}`);
    log(`password candidates tried against: ${candidates.join(", ") || "(none — add @hints or --accounts)"}\n`);
    // law-allow: clockDefault — provenance date in the vault comment line, not ordering
    const today = new Date().toISOString().slice(0, 10);
    let written = 0;
    for (const step of plan) {
        log(`dump:${step.item.lineNo}  ${step.label}`);
        log(`        → hive/${step.account}/keys.txt`);
        if (!write)
            continue;
        const dir = path.join(vaultDir, step.account);
        mkdirSync(dir, { recursive: true, mode: 0o700 });
        const file = path.join(dir, "keys.txt");
        const existing = existsSync(file) ? readFileSync(file, "utf8") : "";
        if (existing.split("\n").some((l) => l.trim() === step.item.line)) {
            log("        (already in vault, skipped)");
            continue;
        }
        if (!existsSync(file)) {
            writeFileSync(file, "", { mode: 0o600 });
        }
        appendFileSync(file, `# ${step.label} — sorted ${today}\n${step.item.line}\n`);
        chmodSync(file, 0o600);
        written += 1;
    }
    if (write) {
        log(`\n${written} item(s) written. Now DELETE the dump: shred -u ${dump}`);
        log("Then run `hive-key identify` for the coverage table.");
    }
    return 0;
}

