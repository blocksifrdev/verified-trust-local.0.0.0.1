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
exports.reportCommand = reportCommand;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const identityGraph_1 = require("../../graph/identityGraph");
const trustRiskScoring_1 = require("../../scoring/trustRiskScoring");
const jsonReporter_1 = require("../../reporters/jsonReporter");
const htmlReporter_1 = require("../../reporters/htmlReporter");
const markdownReporter_1 = require("../../reporters/markdownReporter");
async function reportCommand(findingsJson, opts) {
    const edition = process.env['VT_EDITION'] ?? 'community';
    console.log(`Regenerating reports from: ${findingsJson}`);
    let findings = [];
    try {
        const content = fs.readFileSync(findingsJson, 'utf-8');
        const parsed = JSON.parse(content);
        // Support both array of findings and full NHIGraph format
        if (Array.isArray(parsed)) {
            findings = parsed;
        }
        else if (parsed.findings && Array.isArray(parsed.findings)) {
            findings = parsed.findings;
        }
    }
    catch (err) {
        console.error(`Cannot read findings file: ${findingsJson}`);
        process.exit(1);
    }
    // Try to read accompanying files from same directory
    const findingsDir = path.dirname(findingsJson);
    const graph = new identityGraph_1.IdentityGraph();
    // Load identity map if present
    const identityMapPath = path.join(findingsDir, 'identity-map.json');
    if (fs.existsSync(identityMapPath)) {
        try {
            const identities = JSON.parse(fs.readFileSync(identityMapPath, 'utf-8'));
            if (Array.isArray(identities)) {
                for (const i of identities)
                    graph.addIdentity(i);
            }
        }
        catch { /* ignore */ }
    }
    // Load authority graph if present
    const authorityGraphPath = path.join(findingsDir, 'authority-graph.json');
    if (fs.existsSync(authorityGraphPath)) {
        try {
            const agData = JSON.parse(fs.readFileSync(authorityGraphPath, 'utf-8'));
            if (agData.edges && Array.isArray(agData.edges)) {
                for (const e of agData.edges)
                    graph.addEdge(e);
            }
        }
        catch { /* ignore */ }
    }
    for (const f of findings) {
        graph.addFinding(f);
    }
    const riskScore = (0, trustRiskScoring_1.scoreGraph)(graph);
    fs.mkdirSync(opts.out, { recursive: true });
    await (0, jsonReporter_1.writeJsonReports)(graph, riskScore, opts.out);
    await (0, htmlReporter_1.writeHtmlReport)(graph, riskScore, edition, opts.out);
    await (0, markdownReporter_1.writeMarkdownReport)(graph, riskScore, opts.out);
    console.log(`Reports regenerated. Risk: ${riskScore.total}/100 (${riskScore.band})`);
    console.log(`Output: ${opts.out}`);
}
//# sourceMappingURL=report.js.map