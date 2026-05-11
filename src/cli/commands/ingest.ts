import * as fs from 'fs';
import * as path from 'path';
import { ScanResult } from '../../core/types';
import { entraExportConnector } from '../../connectors/entraExportConnector';
import { oktaExportConnector } from '../../connectors/oktaExportConnector';
import { awsIamExportConnector } from '../../connectors/awsIamExportConnector';
import { azureIamExportConnector } from '../../connectors/azureIamExportConnector';
import { gcpIamExportConnector } from '../../connectors/gcpIamExportConnector';
import { cyberarkExportConnector } from '../../connectors/cyberarkExportConnector';
import { beyondTrustExportConnector } from '../../connectors/beyondTrustExportConnector';
import { delineaExportConnector } from '../../connectors/delineaExportConnector';
import { vaultExportConnector } from '../../connectors/vaultExportConnector';
import { genericCsvConnector } from '../../connectors/genericCsvConnector';
import { genericLogConnector } from '../../connectors/genericLogConnector';

type ConnectorFn = (fileOrDir: string) => ScanResult;

const CONNECTORS: Record<string, ConnectorFn> = {
  entra: entraExportConnector,
  okta: oktaExportConnector,
  aws: awsIamExportConnector,
  azure: azureIamExportConnector,
  gcp: gcpIamExportConnector,
  cyberark: cyberarkExportConnector,
  beyondtrust: beyondTrustExportConnector,
  delinea: delineaExportConnector,
  vault: vaultExportConnector,
  csv: genericCsvConnector,
  log: genericLogConnector,
};

export async function ingestCommand(
  source: string,
  fileOrDir: string,
  opts: { out: string }
): Promise<void> {
  const connector = CONNECTORS[source.toLowerCase()];
  if (!connector) {
    console.error(`Unknown source: "${source}". Supported: ${Object.keys(CONNECTORS).join(', ')}`);
    process.exit(1);
  }

  console.log(`Ingesting ${source} data from ${fileOrDir}...`);
  const result = connector(fileOrDir);
  console.log(`Found ${result.identities.length} identities, ${result.findings.length} findings.`);

  fs.mkdirSync(opts.out, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const outFile = path.join(opts.out, `${source}-${timestamp}.json`);

  fs.writeFileSync(outFile, JSON.stringify(result, null, 2), 'utf-8');
  console.log(`Saved to: ${outFile}`);
}
