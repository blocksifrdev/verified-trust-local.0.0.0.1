import { InflectionPoint, InflectionPointType, Severity } from './types';
export declare function createInflectionPoint(partial: Partial<InflectionPoint> & {
    type: InflectionPointType;
    severity: Severity;
    description: string;
    recommendation: string;
}): InflectionPoint;
//# sourceMappingURL=inflectionPoint.d.ts.map