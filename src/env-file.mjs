const LINE_PATTERN = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/u;

function unquote(rawValue) {
  const value = rawValue.trim();
  if (value.length >= 2 && ((value[0] === '"' && value.at(-1) === '"') || (value[0] === "'" && value.at(-1) === "'"))) {
    return value.slice(1, -1);
  }
  return value;
}

/**
 * Parses `.env`-shaped text (`KEY=VALUE` lines, optional `export`, `#` comments, blank lines,
 * single/double-quoted values) into a plain name-to-value object, without touching
 * `process.env` or any filesystem. Pure text transformation -- the caller reads the file.
 * @param {string} text
 * @returns {Readonly<Record<string, string>>}
 */
export function parseEnvFileText(text) {
  const variables = {};
  for (const rawLine of text.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith("#")) continue;
    const match = LINE_PATTERN.exec(rawLine);
    if (!match) continue;
    variables[match[1]] = unquote(match[2]);
  }
  return Object.freeze(variables);
}
