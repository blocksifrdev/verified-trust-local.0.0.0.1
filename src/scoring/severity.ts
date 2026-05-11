import { Severity } from '../core/types';

export function severityToScore(severity: Severity): number {
  switch (severity) {
    case 'CRITICAL': return 100;
    case 'HIGH': return 75;
    case 'MODERATE': return 50;
    case 'LOW': return 25;
    case 'INFO': return 5;
  }
}

export function scoreToSeverity(score: number): Severity {
  if (score >= 75) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 25) return 'MODERATE';
  if (score >= 5) return 'LOW';
  return 'INFO';
}

export function aggregateSeverity(severities: Severity[]): Severity {
  if (severities.length === 0) return 'INFO';
  const scores = severities.map(severityToScore);
  const max = Math.max(...scores);
  return scoreToSeverity(max);
}
