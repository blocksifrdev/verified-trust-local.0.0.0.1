import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { discoverFiles } from '../../src/core/fileDiscovery';

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'vt-test-'));
}

describe('discoverFiles', () => {
  it('discovers files in a directory', async () => {
    const tmpDir = makeTempDir();
    try {
      fs.writeFileSync(path.join(tmpDir, 'config.yml'), 'hello: world');
      fs.writeFileSync(path.join(tmpDir, 'main.ts'), 'const x = 1;');

      const files = await discoverFiles(tmpDir);
      expect(files.length).toBe(2);
      expect(files.some((f) => f.path.endsWith('config.yml'))).toBe(true);
      expect(files.some((f) => f.path.endsWith('main.ts'))).toBe(true);
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it('ignores node_modules directory', async () => {
    const tmpDir = makeTempDir();
    try {
      fs.mkdirSync(path.join(tmpDir, 'node_modules', 'some-package'), { recursive: true });
      fs.writeFileSync(path.join(tmpDir, 'node_modules', 'some-package', 'index.js'), 'module.exports = {}');
      fs.writeFileSync(path.join(tmpDir, 'index.ts'), 'const x = 1;');

      const files = await discoverFiles(tmpDir);
      expect(files.every((f) => !f.path.includes('node_modules'))).toBe(true);
      expect(files.some((f) => f.path.endsWith('index.ts'))).toBe(true);
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it('ignores .git directory', async () => {
    const tmpDir = makeTempDir();
    try {
      fs.mkdirSync(path.join(tmpDir, '.git'), { recursive: true });
      fs.writeFileSync(path.join(tmpDir, '.git', 'HEAD'), 'ref: refs/heads/main');
      fs.writeFileSync(path.join(tmpDir, 'app.ts'), 'export {}');

      const files = await discoverFiles(tmpDir);
      expect(files.every((f) => !f.path.includes('/.git/'))).toBe(true);
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it('ignores dist directory', async () => {
    const tmpDir = makeTempDir();
    try {
      fs.mkdirSync(path.join(tmpDir, 'dist'), { recursive: true });
      fs.writeFileSync(path.join(tmpDir, 'dist', 'index.js'), 'compiled');
      fs.writeFileSync(path.join(tmpDir, 'src.ts'), 'export {}');

      const files = await discoverFiles(tmpDir);
      expect(files.every((f) => !f.path.includes('/dist/'))).toBe(true);
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it('ignores binary extensions', async () => {
    const tmpDir = makeTempDir();
    try {
      fs.writeFileSync(path.join(tmpDir, 'app.exe'), Buffer.alloc(100));
      fs.writeFileSync(path.join(tmpDir, 'image.jpg'), Buffer.alloc(100));
      fs.writeFileSync(path.join(tmpDir, 'config.yml'), 'hello: world');

      const files = await discoverFiles(tmpDir);
      expect(files.every((f) => !f.path.endsWith('.exe') && !f.path.endsWith('.jpg'))).toBe(true);
      expect(files.some((f) => f.path.endsWith('config.yml'))).toBe(true);
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it('ignores files larger than 2MB', async () => {
    const tmpDir = makeTempDir();
    try {
      const largeBuffer = Buffer.alloc(3 * 1024 * 1024); // 3MB
      fs.writeFileSync(path.join(tmpDir, 'large.txt'), largeBuffer);
      fs.writeFileSync(path.join(tmpDir, 'small.txt'), 'small content');

      const files = await discoverFiles(tmpDir);
      expect(files.every((f) => !f.path.endsWith('large.txt'))).toBe(true);
      expect(files.some((f) => f.path.endsWith('small.txt'))).toBe(true);
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });
});
