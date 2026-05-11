import { RiskScore } from '../core/types';
import { IdentityGraph } from '../graph/identityGraph';
export declare function writeHtmlReport(graph: IdentityGraph, riskScore: RiskScore, edition: string, outputDir: string): Promise<void>;
export declare function generateHtmlReport(graph: IdentityGraph, riskScore: RiskScore, edition: string): string;
//# sourceMappingURL=htmlReporter.d.ts.map