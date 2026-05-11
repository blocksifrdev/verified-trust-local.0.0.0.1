#!/usr/bin/env node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const commander_1 = require("commander");
const scan_1 = require("./commands/scan");
const ingest_1 = require("./commands/ingest");
const analyze_1 = require("./commands/analyze");
const report_1 = require("./commands/report");
const doctor_1 = require("./commands/doctor");
const activate_1 = require("./commands/activate");
const program = new commander_1.Command();
program
    .name('verifiedtrust')
    .description('Open-source, local-first non-human identity authority graph and execution inflection scanner')
    .version('0.1.0');
program
    .command('scan <path>')
    .description('Scan a directory for non-human identities, execution paths, and inflection points')
    .option('--out <outputDir>', 'Output directory for reports', './verifiedtrust-report')
    .option('--edition <edition>', 'Edition (community, pro, business, enterprise)', 'community')
    .action(async (scanPath, opts) => {
    try {
        await (0, scan_1.scanCommand)(scanPath, opts);
    }
    catch (err) {
        console.error('Scan failed:', err instanceof Error ? err.message : String(err));
        process.exit(1);
    }
});
program
    .command('ingest <source> <fileOrDir>')
    .description('Ingest an offline export from an identity provider or PAM tool')
    .option('--out <dataDir>', 'Output directory for ingested data', './vt-data')
    .action(async (source, fileOrDir, opts) => {
    try {
        await (0, ingest_1.ingestCommand)(source, fileOrDir, opts);
    }
    catch (err) {
        console.error('Ingest failed:', err instanceof Error ? err.message : String(err));
        process.exit(1);
    }
});
program
    .command('analyze <dataDir>')
    .description('Analyze previously ingested data')
    .option('--out <outputDir>', 'Output directory for reports', './verifiedtrust-report')
    .action(async (dataDir, opts) => {
    try {
        await (0, analyze_1.analyzeCommand)(dataDir, opts);
    }
    catch (err) {
        console.error('Analysis failed:', err instanceof Error ? err.message : String(err));
        process.exit(1);
    }
});
program
    .command('report <findingsJson>')
    .description('Regenerate reports from an existing findings.json file')
    .option('--out <outputDir>', 'Output directory for reports', './verifiedtrust-report')
    .action(async (findingsJson, opts) => {
    try {
        await (0, report_1.reportCommand)(findingsJson, opts);
    }
    catch (err) {
        console.error('Report generation failed:', err instanceof Error ? err.message : String(err));
        process.exit(1);
    }
});
program
    .command('doctor')
    .description('Check the environment and print diagnostic information')
    .action(async () => {
    try {
        await (0, doctor_1.doctorCommand)();
    }
    catch (err) {
        console.error('Doctor check failed:', err instanceof Error ? err.message : String(err));
        process.exit(1);
    }
});
program
    .command('activate')
    .description('Activate a Pro/Business/Enterprise license key')
    .requiredOption('--license <licenseKey>', 'License key to activate')
    .action(async (opts) => {
    try {
        await (0, activate_1.activateCommand)(opts);
    }
    catch (err) {
        console.error('Activation failed:', err instanceof Error ? err.message : String(err));
        process.exit(1);
    }
});
program.parse(process.argv);
//# sourceMappingURL=index.js.map