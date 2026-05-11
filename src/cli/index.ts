#!/usr/bin/env node

import { Command } from 'commander';
import { scanCommand } from './commands/scan';
import { ingestCommand } from './commands/ingest';
import { analyzeCommand } from './commands/analyze';
import { reportCommand } from './commands/report';
import { doctorCommand } from './commands/doctor';
import { activateCommand } from './commands/activate';

const program = new Command();

program
  .name('verifiedtrust')
  .description('Open-source, local-first non-human identity authority graph and execution inflection scanner')
  .version('0.1.0');

program
  .command('scan <path>')
  .description('Scan a directory for non-human identities, execution paths, and inflection points')
  .option('--out <outputDir>', 'Output directory for reports', './verifiedtrust-report')
  .option('--edition <edition>', 'Edition (community, pro, business, enterprise)', 'community')
  .action(async (scanPath: string, opts: { out: string; edition?: string }) => {
    try {
      await scanCommand(scanPath, opts);
    } catch (err) {
      console.error('Scan failed:', err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  });

program
  .command('ingest <source> <fileOrDir>')
  .description('Ingest an offline export from an identity provider or PAM tool')
  .option('--out <dataDir>', 'Output directory for ingested data', './vt-data')
  .action(async (source: string, fileOrDir: string, opts: { out: string }) => {
    try {
      await ingestCommand(source, fileOrDir, opts);
    } catch (err) {
      console.error('Ingest failed:', err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  });

program
  .command('analyze <dataDir>')
  .description('Analyze previously ingested data')
  .option('--out <outputDir>', 'Output directory for reports', './verifiedtrust-report')
  .action(async (dataDir: string, opts: { out: string }) => {
    try {
      await analyzeCommand(dataDir, opts);
    } catch (err) {
      console.error('Analysis failed:', err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  });

program
  .command('report <findingsJson>')
  .description('Regenerate reports from an existing findings.json file')
  .option('--out <outputDir>', 'Output directory for reports', './verifiedtrust-report')
  .action(async (findingsJson: string, opts: { out: string }) => {
    try {
      await reportCommand(findingsJson, opts);
    } catch (err) {
      console.error('Report generation failed:', err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  });

program
  .command('doctor')
  .description('Check the environment and print diagnostic information')
  .action(async () => {
    try {
      await doctorCommand();
    } catch (err) {
      console.error('Doctor check failed:', err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  });

program
  .command('activate')
  .description('Activate a Pro/Business/Enterprise license key')
  .requiredOption('--license <licenseKey>', 'License key to activate')
  .action(async (opts: { license: string }) => {
    try {
      await activateCommand(opts);
    } catch (err) {
      console.error('Activation failed:', err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  });

program.parse(process.argv);
