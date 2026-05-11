import * as fs from 'fs';
import * as path from 'path';

const IGNORE_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'vendor', 'target',
  '.next', 'coverage', '.cache', '__pycache__',
]);

const IGNORE_EXTENSIONS = new Set([
  '.exe', '.dll', '.so', '.dylib', '.bin',
  '.jpg', '.jpeg', '.png', '.gif', '.ico',
  '.pdf', '.zip', '.tar', '.gz',
]);

const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024; // 2MB

export interface DiscoveredFile {
  path: string;
  size: number;
  extension: string;
}

export async function discoverFiles(rootPath: string): Promise<DiscoveredFile[]> {
  const results: DiscoveredFile[] = [];
  await walk(rootPath, results);
  return results;
}

async function walk(dir: string, results: DiscoveredFile[]): Promise<void> {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      if (IGNORE_DIRS.has(entry.name)) continue;
      await walk(fullPath, results);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (IGNORE_EXTENSIONS.has(ext)) continue;

      let stat: fs.Stats;
      try {
        stat = fs.statSync(fullPath);
      } catch {
        continue;
      }

      if (stat.size > MAX_FILE_SIZE_BYTES) continue;

      results.push({
        path: fullPath,
        size: stat.size,
        extension: ext,
      });
    }
  }
}
