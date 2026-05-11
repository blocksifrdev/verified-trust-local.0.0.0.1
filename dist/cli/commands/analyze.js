"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeCommand = analyzeCommand;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const graphBuilder_1 = require("../../graph/graphBuilder");
const inflectionPointDetector_1 = require("../../detectors/inflectionPointDetector");
const evidenceGapDetector_1 = require("../../detectors/evidenceGapDetector");
const effortDecayDetector_1 = require("../../detectors/effortDecayDetector");
const trustRiskScoring_1 = require("../../scoring/trustRiskScoring");
const jsonReporter_1 = require("../../reporters/jsonReporter");
const htmlReporter_1 = require("../../reporters/htmlReporter");
const markdownReporter_1 = require("../../reporters/markdownReporter");
async function analyzeCommand(dataDir, opts) {
    const edition = process.env['VT_EDITION'] ?? 'community';
    console.log(`Analyzing ingested data from: ${dataDir}`);
    // Read all JSON files from dataDir
    let jsonFiles = [];
    try {
        jsonFiles = fs.readdirSync(dataDir)
            .filter((f) => f.endsWith('.json'))
            .map((f) => path.join(dataDir, f));
    }
    catch (err) {
        console.error(`Cannot read data directory: ${dataDir}`);
        process.exit(1);
    }
    if (jsonFiles.length === 0) {
        console.error('No .json files found in data directory. Run "verifiedtrust ingest" first.');
        process.exit(1);
    }
    const scanResults = [];
    for (const jsonFile of jsonFiles) {
        try {
            const content = fs.readFileSync(jsonFile, 'utf-8');
            const result = JSON.parse(content);
            scanResults.push(result);
        }
        catch {
            console.warn(`Skipping malformed file: ${jsonFile}`);
        }
    }
    console.log(`Loaded ${scanResults.length} data files with ${scanResults.flatMap((r) => r.identities).length} total identities.`);
    const graph = (0, graphBuilder_1.buildGraph)(scanResults);
    // Run post-graph detectors
    const identities = Array.from(graph.identities.values());
    const inflectionPoints = (0, inflectionPointDetector_1.detectInflectionPoints)(graph);
    const effortDecay = (0, effortDecayDetector_1.detectEffortDecay)(identities);
    const evidenceGaps = (0, evidenceGapDetector_1.detectEvidenceGaps)([], graph);
    for (const ip of [...inflectionPoints, ...effortDecay]) {
        graph.addInflectionPoint(ip);
    }
    for (const f of evidenceGaps) {
        graph.addFinding(f);
    }
    const riskScore = (0, trustRiskScoring_1.scoreGraph)(graph);
    fs.mkdirSync(opts.out, { recursive: true });
    await (0, jsonReporter_1.writeJsonReports)(graph, riskScore, opts.out);
    await (0, htmlReporter_1.writeHtmlReport)(graph, riskScore, edition, opts.out);
    await (0, markdownReporter_1.writeMarkdownReport)(graph, riskScore, opts.out);
    console.log(`Analysis complete. Risk: ${riskScore.total}/100 (${riskScore.band})`);
    console.log(`Reports written to: ${opts.out}`);
}
//# sourceMappingURL=analyze.js.map