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
exports.writeJsonReports = writeJsonReports;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const edition_1 = require("../core/edition");
const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'INFO'];
async function writeJsonReports(graph, riskScore, outputDir) {
    fs.mkdirSync(outputDir, { recursive: true });
    const graphData = graph.toJSON();
    // findings.json — sorted by severity
    const sortedFindings = [...graphData.findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
    fs.writeFileSync(path.join(outputDir, 'findings.json'), JSON.stringify(sortedFindings, null, 2), 'utf-8');
    // identity-map.json
    fs.writeFileSync(path.join(outputDir, 'identity-map.json'), JSON.stringify(graphData.identities, null, 2), 'utf-8');
    // authority-graph.json
    fs.writeFileSync(path.join(outputDir, 'authority-graph.json'), JSON.stringify({ identities: graphData.identities, edges: graphData.edges }, null, 2), 'utf-8');
    // evidence-map.json
    fs.writeFileSync(path.join(outputDir, 'evidence-map.json'), JSON.stringify(graphData.evidenceRefs, null, 2), 'utf-8');
    // risk-summary.json
    const criticalCount = sortedFindings.filter((f) => f.severity === 'CRITICAL').length;
    const highCount = sortedFindings.filter((f) => f.severity === 'HIGH').length;
    const moderateCount = sortedFindings.filter((f) => f.severity === 'MODERATE').length;
    const lowCount = sortedFindings.filter((f) => f.severity === 'LOW').length;
    const totalNHIs = graphData.identities.length;
    const isLimited = totalNHIs >= 25;
    const riskSummary = {
        riskScore,
        totalNHIs,
        criticalCount,
        highCount,
        moderateCount,
        lowCount,
        topFindings: sortedFindings.slice(0, 10).map((f) => ({
            id: f.id,
            severity: f.severity,
            title: f.title,
        })),
        ...(isLimited ? { upgradeMessage: edition_1.UPGRADE_MESSAGE } : {}),
        generatedAt: new Date().toISOString(),
    };
    fs.writeFileSync(path.join(outputDir, 'risk-summary.json'), JSON.stringify(riskSummary, null, 2), 'utf-8');
}
//# sourceMappingURL=jsonReporter.js.map