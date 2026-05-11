export const SECRET_PATTERNS: RegExp[] = [
  // AWS Access Keys
  /AKIA[0-9A-Z]{16}/,
  /ASIA[0-9A-Z]{16}/,
  // GitHub tokens
  /ghp_[A-Za-z0-9]{36}/,
  /ghs_[A-Za-z0-9]{36}/,
  /github_pat_[A-Za-z0-9_]{82}/,
  /gho_[A-Za-z0-9]{36}/,
  /ghu_[A-Za-z0-9]{36}/,
  // Private key markers
  /-----BEGIN RSA PRIVATE KEY-----/,
  /-----BEGIN PRIVATE KEY-----/,
  /-----BEGIN EC PRIVATE KEY-----/,
  /-----BEGIN OPENSSH PRIVATE KEY-----/,
  /-----BEGIN PGP PRIVATE KEY BLOCK-----/,
  // Azure client secrets / connection strings
  /DefaultEndpointsProtocol=https;AccountName=/,
  /AccountKey=[A-Za-z0-9+/=]{64,}/,
  // GCP service account key JSON patterns
  /"private_key":\s*"-----BEGIN/,
  /"type":\s*"service_account"/,
  // Connection strings
  /(?:mysql|postgres|postgresql|mongodb|mssql|redis):\/\/[^:]+:[^@]+@/i,
  // Generic secrets in env-like patterns
  /(?:SECRET|PASSWORD|PASSWD|PASS|PWD|TOKEN|API_KEY|APIKEY|AUTH|CREDENTIAL)=["']?[A-Za-z0-9+/=!@#$%^&*()-_]{8,}/i,
  // High entropy strings (base64-like, 40+ chars)
  /[A-Za-z0-9+/]{40,}={0,2}/,
  // Bearer tokens
  /Bearer\s+[A-Za-z0-9\-._~+/]+=*/i,
];

export function containsSecret(value: string): boolean {
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.test(value)) {
      return true;
    }
  }
  return false;
}

export function redactSecret(value: string): string {
  if (value.length < 8) {
    return '[REDACTED]';
  }
  const first = value.slice(0, 3);
  const last = value.slice(-3);
  return `${first}***${last}`;
}
