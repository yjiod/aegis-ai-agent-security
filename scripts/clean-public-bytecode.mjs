import { readdir, rm } from 'node:fs/promises';
import { resolve } from 'node:path';

const publicRoot = resolve(process.cwd(), 'public');

async function clean(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name);
    if (!path.startsWith(`${publicRoot}/`)) throw new Error('cleanup escaped public root');
    if (entry.isDirectory() && entry.name === '__pycache__') await rm(path, { recursive: true });
    else if (entry.isDirectory()) await clean(path);
    else if (entry.isFile() && /\.py[co]$/.test(entry.name)) await rm(path);
  }
}

await clean(publicRoot);
