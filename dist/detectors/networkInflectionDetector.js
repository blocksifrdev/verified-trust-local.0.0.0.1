"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectNetworkInflections = detectNetworkInflections;
const inflectionPoint_1 = require("../core/inflectionPoint");
function detectNetworkInflections(identities, executionPaths) {
    const inflectionPoints = [];
    for (const ep of executionPaths) {
        // TRUST_BOUNDARY_CROSSING
        if (ep.trustBoundaryCrossed) {
            inflectionPoints.push((0, inflectionPoint_1.createInflectionPoint)({
                type: 'TRUST_BOUNDARY_CROSSING',
                severity: 'HIGH',
                identityId: ep.identityId,
                identityName: ep.identityName,
                executionPathId: ep.id,
                description: `Network trust boundary crossing detected: "${ep.identityName}" executes across boundary to "${ep.targetEnvironment}"`,
                recommendation: 'Enforce network segmentation and mutual TLS at trust boundaries. Ensure crossing is authorized and logged.',
                sourceFile: ep.sourceFile,
                metadata: { trigger: ep.trigger, environment: ep.targetEnvironment },
            }));
        }
        // SERVICE_TO_SERVICE_PATH
        const identity = identities.find((i) => i.id === ep.identityId);
        if (identity &&
            (identity.identityType === 'service_account' || identity.identityType === 'service_principal') &&
            ep.steps.length > 1) {
            inflectionPoints.push((0, inflectionPoint_1.createInflectionPoint)({
                type: 'SERVICE_TO_SERVICE_PATH',
                severity: 'MODERATE',
                identityId: ep.identityId,
                identityName: ep.identityName,
                executionPathId: ep.id,
                description: `Service-to-service execution path detected: "${ep.identityName}" with ${ep.steps.length} steps`,
                recommendation: 'Implement workload identity federation for service-to-service authentication instead of long-lived credentials.',
                sourceFile: ep.sourceFile,
                metadata: { steps: ep.steps },
            }));
        }
        // PUBLIC_EXPOSURE
        if (ep.isProduction &&
            !ep.approvalDetected &&
            ep.targetEnvironment.toLowerCase().includes('public')) {
            inflectionPoints.push((0, inflectionPoint_1.createInflectionPoint)({
                type: 'PUBLIC_EXPOSURE',
                severity: 'CRITICAL',
                identityId: ep.identityId,
                identityName: ep.identityName,
                executionPathId: ep.id,
                description: `Identity "${ep.identityName}" has unapproved execution path to public-facing environment`,
                recommendation: 'Require explicit approval for any deployment to public-facing infrastructure.',
                sourceFile: ep.sourceFile,
                metadata: { environment: ep.targetEnvironment },
            }));
        }
    }
    return inflectionPoints;
}
//# sourceMappingURL=networkInflectionDetector.js.map