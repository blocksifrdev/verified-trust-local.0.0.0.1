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
exports.discoverFiles = discoverFiles;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const IGNORE_DIRS = new Set([
    'node_modules', '.git', 'dist', 'build', 'vendor', 'target',
    '.next', 'coverage', '.cache', '__pycache__',
]);
const IGNORE_EXTENSIONS = new Set([
    '.exe', '.dll', '.so', '.dylib', '.bin',
    '.jpg', '.jpeg', '.png', '.gif', '.ico',
    '.pdf', '.zip', '.tar', '.gz',
]);
const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024; // 2MB
async function discoverFiles(rootPath) {
    const results = [];
    await walk(rootPath, results);
    return results;
}
async function walk(dir, results) {
    let entries;
    try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
    }
    catch {
        return;
    }
    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            if (IGNORE_DIRS.has(entry.name))
                continue;
            await walk(fullPath, results);
        }
        else if (entry.isFile()) {
            const ext = path.extname(entry.name).toLowerCase();
            if (IGNORE_EXTENSIONS.has(ext))
                continue;
            let stat;
            try {
                stat = fs.statSync(fullPath);
            }
            catch {
                continue;
            }
            if (stat.size > MAX_FILE_SIZE_BYTES)
                continue;
            results.push({
                path: fullPath,
                size: stat.size,
                extension: ext,
            });
        }
    }
}
//# sourceMappingURL=fileDiscovery.js.map