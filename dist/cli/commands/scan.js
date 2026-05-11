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
exports.scanCommand = scanCommand;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const fileDiscovery_1 = require("../../core/fileDiscovery");
const limits_1 = require("../../core/limits");
const normalization_1 = require("../../core/normalization");
const fileSystemConnector_1 = require("../../connectors/fileSystemConnector");
const githubActionsConnector_1 = require("../../connectors/githubActionsConnector");
const azureDevOpsConnector_1 = require("../../connectors/azureDevOpsConnector");
const gitlabCiConnector_1 = require("../../connectors/gitlabCiConnector");
const jenkinsConnector_1 = require("../../connectors/jenkinsConnector");
const terraformConnector_1 = require("../../connectors/terraformConnector");
const kubernetesConnector_1 = require("../../connectors/kubernetesConnector");
const nhiDetector_1 = require("../../detectors/nhiDetector");
const inflectionPointDetector_1 = require("../../detectors/inflectionPointDetector");
const credentialRiskDetector_1 = require("../../detectors/credentialRiskDetector");
const executionPathDetector_1 = require("../../detectors/executionPathDetector");
const networkInflectionDetector_1 = require("../../detectors/networkInflectionDetector");
const evidenceGapDetector_1 = require("../../detectors/evidenceGapDetector");
const effortDecayDetector_1 = require("../../detectors/effortDecayDetector");
const aiAgentDetector_1 = require("../../detectors/aiAgentDetector");
const graphBuilder_1 = require("../../graph/graphBuilder");
const trustRiskScoring_1 = require("../../scoring/trustRiskScoring");
const jsonReporter_1 = require("../../reporters/jsonReporter");
const htmlReporter_1 = require("../../reporters/htmlReporter");
const markdownReporter_1 = require("../../reporters/markdownReporter");
async function scanCommand(scanPath, opts) {
    const edition = opts.edition ?? process.env['VT_EDITION'] ?? 'community';
    const outputDir = opts.out;
    console.log('');
    console.log('VerifiedTrust Local — Non-Human Identity + Execution Surface Assessment');
    console.log('=========================================================================');
    console.log(`Scanning: ${path.resolve(scanPath)}`);
    console.log(`Output:   ${path.resolve(outputDir)}`);
    console.log(`Edition:  ${edition.toUpperCase()}`);
    console.log('');
    // 1. Discover files
    process.stdout.write('Discovering files...');
    const files = await (0, fileDiscovery_1.discoverFiles)(path.resolve(scanPath));
    console.log(` ${files.length} files found`);
    // Pre-load file contents for efficiency
    const fileContents = new Map();
    // 2. Run all connectors
    process.stdout.write('Running connectors...');
    const scanResults = [];
    scanResults.push((0, fileSystemConnector_1.fileSystemConnector)(files, fileContents));
    scanResults.push((0, githubActionsConnector_1.githubActionsConnector)(files, fileContents));
    scanResults.push((0, azureDevOpsConnector_1.azureDevOpsConnector)(files, fileContents));
    scanResults.push((0, gitlabCiConnector_1.gitlabCiConnector)(files, fileContents));
    scanResults.push((0, jenkinsConnector_1.jenkinsConnector)(files, fileContents));
    scanResults.push((0, terraformConnector_1.terraformConnector)(files, fileContents));
    scanResults.push((0, kubernetesConnector_1.kubernetesConnector)(files, fileContents));
    console.log(' done');
    // 3. Run detectors
    process.stdout.write('Running detectors...');
    const allIdentities = scanResults.flatMap((r) => r.identities);
    // NHI detector
    const nhiIdentities = (0, nhiDetector_1.detectNHIs)(files, fileContents);
    const credentialFindings = (0, credentialRiskDetector_1.detectCredentialRisks)(files, fileContents);
    const { identities: agentIdentities, inflectionPoints: agentInflections } = (0, aiAgentDetector_1.detectAIAgents)(files, fileContents);
    // Create a synthetic scan result for detected NHIs
    scanResults.push({
        identities: [...nhiIdentities, ...agentIdentities],
        edges: [],
        executionPaths: [],
        inflectionPoints: agentInflections,
        findings: credentialFindings,
        evidenceRefs: [],
        sourceSystem: 'filesystem',
    });
    console.log(' done');
    // 4. Build graph
    process.stdout.write('Building identity graph...');
    const graph = (0, graphBuilder_1.buildGraph)(scanResults);
    console.log(` ${graph.identities.size} identities`);
    // 5. Normalize and apply edition limits
    const allIdentitiesNormalized = (0, normalization_1.normalizeIdentities)(Array.from(graph.identities.values()));
    const { items: limitedIdentities, limited, total } = (0, limits_1.applyEditionLimit)(allIdentitiesNormalized, edition);
    // Rebuild identities map with limited set
    graph.identities.clear();
    for (const identity of limitedIdentities) {
        graph.identities.set(identity.id, identity);
    }
    // 6. Run post-graph detectors
    process.stdout.write('Detecting execution paths...');
    const execPaths = (0, executionPathDetector_1.detectExecutionPaths)(limitedIdentities, files, fileContents);
    for (const ep of execPaths) {
        graph.addExecutionPath(ep);
    }
    const networkInflections = (0, networkInflectionDetector_1.detectNetworkInflections)(limitedIdentities, graph.executionPaths);
    const inflectionPoints = (0, inflectionPointDetector_1.detectInflectionPoints)(graph);
    const evidenceGapFindings = (0, evidenceGapDetector_1.detectEvidenceGaps)(files, graph);
    const effortDecayInflections = (0, effortDecayDetector_1.detectEffortDecay)(limitedIdentities);
    for (const ip of [...inflectionPoints, ...networkInflections, ...effortDecayInflections]) {
        graph.addInflectionPoint(ip);
    }
    for (const finding of evidenceGapFindings) {
        graph.addFinding(finding);
    }
    console.log(' done');
    // 7. Score risk
    const riskScore = (0, trustRiskScoring_1.scoreGraph)(graph);
    // 8. Generate reports
    process.stdout.write('Generating reports...');
    fs.mkdirSync(outputDir, { recursive: true });
    await (0, jsonReporter_1.writeJsonReports)(graph, riskScore, outputDir);
    await (0, htmlReporter_1.writeHtmlReport)(graph, riskScore, edition, outputDir);
    await (0, markdownReporter_1.writeMarkdownReport)(graph, riskScore, outputDir);
    console.log(' done');
    // 9. Print summary
    console.log('');
    console.log('=== Scan Complete ===');
    console.log(`Risk Score:  ${riskScore.total}/100 (${riskScore.band})`);
    console.log(`NHIs Found:  ${total} total${limited ? `, ${limitedIdentities.length} analyzed (Community Edition limit)` : ''}`);
    console.log(`Findings:    ${graph.findings.length}`);
    console.log(`Reports:     ${path.resolve(outputDir)}`);
    console.log('');
    console.log(`  executive-report.html   — Executive HTML report`);
    console.log(`  findings.json           — All findings sorted by severity`);
    console.log(`  identity-map.json       — NHI inventory`);
    console.log(`  authority-graph.json    — Identity authority graph`);
    console.log(`  evidence-map.json       — Evidence artifacts detected`);
    console.log(`  risk-summary.json       — Risk score summary`);
    console.log(`  remediation-roadmap.md  — 30-day remediation plan`);
    console.log('');
    if (limited) {
        console.log('NOTE: Community Edition limit reached. Run with --edition pro for full analysis.');
        console.log('      Upgrade at https://verifiedtrust.io');
        console.log('');
    }
}
//# sourceMappingURL=scan.js.map