import { scanCommand } from '../cli/commands/scan';

function getInput(name: string, fallback: string): string {
  const envName = `INPUT_${name.toUpperCase().replace(/-/g, '_')}`;
  const legacyEnvName = `INPUT_${name.toUpperCase()}`;
  return (process.env[envName] ?? process.env[legacyEnvName] ?? fallback).trim();
}

async function main(): Promise<void> {
  const scanPath = getInput('scan-path', '.');
  const out = getInput('output-dir', 'verifiedtrust-report');
  const edition = getInput('edition', 'community');

  await scanCommand(scanPath, { out, edition });
}

main().catch((err) => {
  console.error('VerifiedTrust Action failed:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
