import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { loadLicense } from '../../core/localLicense';

interface DoctorCheck {
  name: string;
  status: 'PASS' | 'WARN' | 'FAIL';
  message: string;
}

export async function doctorCommand(): Promise<void> {
  console.log('');
  console.log('VerifiedTrust Local — Diagnostic Check');
  console.log('=======================================');
  console.log('');

  const checks: DoctorCheck[] = [];

  // Check Node.js version
  const nodeVersion = process.version;
  const nodeMajor = parseInt(nodeVersion.slice(1).split('.')[0], 10);
  checks.push({
    name: 'Node.js Version',
    status: nodeMajor >= 18 ? 'PASS' : 'FAIL',
    message: `${nodeVersion} (requires >=18)`,
  });

  // Check output dir writable
  const testDir = path.join(os.tmpdir(), 'verifiedtrust-doctor-test');
  try {
    fs.mkdirSync(testDir, { recursive: true });
    fs.writeFileSync(path.join(testDir, 'test.txt'), 'ok', 'utf-8');
    fs.rmSync(testDir, { recursive: true });
    checks.push({
      name: 'Write Access (tmp)',
      status: 'PASS',
      message: `${os.tmpdir()} is writable`,
    });
  } catch {
    checks.push({
      name: 'Write Access (tmp)',
      status: 'FAIL',
      message: `Cannot write to ${os.tmpdir()}`,
    });
  }

  // No network required
  checks.push({
    name: 'Network Required',
    status: 'PASS',
    message: 'VerifiedTrust Local makes no network calls. All processing is local.',
  });

  // Edition info
  let edition = 'community';
  try {
    const license = loadLicense();
    edition = license.edition;
  } catch { /* community */ }

  const envEdition = process.env['VT_EDITION'];
  checks.push({
    name: 'Edition',
    status: 'PASS',
    message: `${edition.toUpperCase()}${envEdition ? ` (overridden by VT_EDITION env var: ${envEdition})` : ''}`,
  });

  // Version
  checks.push({
    name: 'VerifiedTrust Local Version',
    status: 'PASS',
    message: 'v0.1.0',
  });

  // License file
  const licensePath = path.join(os.homedir(), '.verifiedtrust', 'license.json');
  const hasLicense = fs.existsSync(licensePath);
  checks.push({
    name: 'License File',
    status: hasLicense ? 'PASS' : 'WARN',
    message: hasLicense
      ? `Found at ${licensePath}`
      : `Not found (${licensePath}). Using community edition. Run "verifiedtrust activate" to activate.`,
  });

  // Print results
  const maxNameLen = Math.max(...checks.map((c) => c.name.length));
  for (const check of checks) {
    const statusLabel =
      check.status === 'PASS' ? '[PASS]' :
      check.status === 'WARN' ? '[WARN]' :
      '[FAIL]';
    const paddedName = check.name.padEnd(maxNameLen + 2);
    console.log(`  ${statusLabel}  ${paddedName}${check.message}`);
  }

  const failures = checks.filter((c) => c.status === 'FAIL');
  const warnings = checks.filter((c) => c.status === 'WARN');

  console.log('');
  if (failures.length > 0) {
    console.log(`Doctor found ${failures.length} failure(s) and ${warnings.length} warning(s).`);
    process.exit(1);
  } else if (warnings.length > 0) {
    console.log(`Doctor found ${warnings.length} warning(s). VerifiedTrust Local should work correctly.`);
  } else {
    console.log('All checks passed. VerifiedTrust Local is ready.');
  }
  console.log('');
}
