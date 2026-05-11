export interface DiscoveredFile {
    path: string;
    size: number;
    extension: string;
}
export declare function discoverFiles(rootPath: string): Promise<DiscoveredFile[]>;
//# sourceMappingURL=fileDiscovery.d.ts.map