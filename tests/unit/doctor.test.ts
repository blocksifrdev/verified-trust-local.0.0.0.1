import { describe, it, expect, vi } from 'vitest';
import { doctorCommand } from '../../src/cli/commands/doctor';

describe('doctorCommand', () => {
  it('runs without throwing', async () => {
    // Suppress console output for this test
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await expect(doctorCommand()).resolves.not.toThrow();

    consoleSpy.mockRestore();
    consoleErrSpy.mockRestore();
  });

  it('outputs version information', async () => {
    const logs: string[] = [];
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation((msg: string) => {
      logs.push(String(msg));
    });

    await doctorCommand();

    expect(logs.some((l) => l.includes('v0.1.0'))).toBe(true);
    consoleSpy.mockRestore();
  });

  it('checks Node.js version', async () => {
    const logs: string[] = [];
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation((msg: string) => {
      logs.push(String(msg));
    });

    await doctorCommand();

    expect(logs.some((l) => l.includes('Node') || l.includes('node'))).toBe(true);
    consoleSpy.mockRestore();
  });
});
