import { RiskScore } from '../core/types';
import { IdentityGraph } from '../graph/identityGraph';
export declare function writeMarkdownReport(graph: IdentityGraph, riskScore: RiskScore, outputDir: string): Promise<void>;
export declare function generateMarkdownReport(graph: IdentityGraph, riskScore: RiskScore): string;
//# sourceMappingURL=markdownReporter.d.ts.map