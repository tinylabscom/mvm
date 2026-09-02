// WebLinux Builder integration with OPFS
//
// Provides a builder that caches Nix build artifacts in OPFS, enabling
// persistent builds across page reloads and reuse across multiple builds.

import { OPFSStore, CachedOPFSStore, sha256Digest } from '../common/opfs-store';
import { OPFSWorkspace, WorkspaceSnapshot } from '../common/opfs-workspace';

export type BuildArtifact = {
  digest: string;
  size: number;
  manifest: BuildManifest;
};

export type BuildManifest = {
  name: string;
  version: string;
  type: 'rootfs' | 'kernel' | 'runtime' | 'nix-store';
  source: {
    type: 'nix' | 'oci' | 'local';
    ref: string;
  };
  dependencies: string[];
};

export type BuildProgress = {
  phase: 'pending' | 'fetching' | 'building' | 'validating' | 'storing' | 'complete';
  progress: number;
  message: string;
  artifact?: BuildArtifact;
};

export type BuildRequest = {
  sourceRef: string;
  sourceDigest?: string;
  workspaceSnapshot?: string;
};

export type BuildResponse = {
  success: boolean;
  artifact?: BuildArtifact;
  error?: string;
  logs: string[];
};

export class WebLinuxBuilder {
  private store: CachedOPFSStore;
  private logs: string[] = [];
  private progressListeners: ((progress: BuildProgress) => void)[] = [];

  constructor(store: CachedOPFSStore) {
    this.store = store;
  }

  static async create(): Promise<WebLinuxBuilder> {
    const store = await CachedOPFSStore.create();
    const builder = new WebLinuxBuilder(store);
    return builder;
  }

  async build(request: BuildRequest): Promise<BuildResponse> {
    this.logs = [];
    this.notifyProgress({ phase: 'pending', progress: 0, message: 'Starting build...' });

    try {
      if (request.sourceDigest) {
        const cacheHit = await this.checkCache(request.sourceDigest);
        if (cacheHit.ok && cacheHit.value) {
          this.notifyProgress({ phase: 'complete', progress: 100, message: 'Cache hit!', artifact: cacheHit.value });
          return { success: true, artifact: cacheHit.value, logs: this.logs };
        }
      }

      this.notifyProgress({ phase: 'fetching', progress: 25, message: 'Fetching source...' });
      const sourceData = await this.fetchSource(request.sourceRef);
      const sourceDigest = await sha256Digest(sourceData);
      this.log(`Fetched source, digest: ${sourceDigest}`);

      this.notifyProgress({ phase: 'building', progress: 50, message: 'Building artifact...' });
      const artifactData = await this.buildArtifact(sourceData, request);
      const artifactDigest = await sha256Digest(artifactData);
      this.log(`Built artifact, digest: ${artifactDigest}`);

      this.notifyProgress({ phase: 'validating', progress: 75, message: 'Validating artifact...' });
      const validation = await this.validateArtifact(artifactData);
      if (!validation.valid) {
        return {
          success: false,
          error: validation.error,
          logs: this.logs,
        };
      }
      this.log('Validation passed');

      this.notifyProgress({ phase: 'storing', progress: 90, message: 'Storing in cache...' });
      await this.cacheArtifact(artifactDigest, artifactData, {
        name: request.sourceRef.split('/').pop() || 'artifact',
        version: '1.0.0',
        type: this.guessArtifactType(request.sourceRef),
        source: { type: 'nix', ref: request.sourceRef },
        dependencies: [],
      });
      this.log('Artifact cached in OPFS');

      const artifact: BuildArtifact = {
        digest: artifactDigest,
        size: artifactData.length,
        manifest: {
          name: request.sourceRef.split('/').pop() || 'artifact',
          version: '1.0.0',
          type: this.guessArtifactType(request.sourceRef),
          source: { type: 'nix', ref: request.sourceRef },
          dependencies: [],
        },
      };

      this.notifyProgress({ phase: 'complete', progress: 100, message: 'Build complete!', artifact });
      return { success: true, artifact, logs: this.logs };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.log(`Build failed: ${errorMessage}`);
      return {
        success: false,
        error: errorMessage,
        logs: this.logs,
      };
    }
  }

  private async checkCache(digest: string): Promise<{ ok: true; value: BuildArtifact | null } | { ok: false; error: string }> {
    try {
      const exists = await this.store.store.exists(digest);
      if (!exists.ok) {
        return { ok: true, value: null };
      }
      if (!exists.value) {
        return { ok: true, value: null };
      }

      const metadataKey = `${digest}.manifest`;
      const metadataExists = await this.store.store.exists(metadataKey);
      if (!metadataExists.ok) {
        return { ok: true, value: null };
      }
      if (!metadataExists.value) {
        return { ok: true, value: null };
      }

      const metadataResult = await this.store.store.get(metadataKey);
      if (!metadataResult.ok) {
        return { ok: true, value: null };
      }

      const manifest: BuildManifest = JSON.parse(new TextDecoder().decode(metadataResult.value));
      const sizeResult = await this.store.store.get(digest);
      if (!sizeResult.ok) {
        return { ok: true, value: null };
      }

      return {
        ok: true,
        value: {
          digest,
          size: sizeResult.value.length,
          manifest,
        },
      };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
  }

  private async fetchSource(ref: string): Promise<Uint8Array> {
    const mockData = new TextEncoder().encode(`mock-source-${ref}`);
    return mockData;
  }

  private async buildArtifact(sourceData: Uint8Array, request: BuildRequest): Promise<Uint8Array> {
    const mockArtifact = new TextEncoder().encode(JSON.stringify({
      type: 'mock-build',
      source: request.sourceRef,
      timestamp: Date.now(),
    }));
    return mockArtifact;
  }

  private async validateArtifact(data: Uint8Array): Promise<{ valid: boolean; error?: string }> {
    try {
      JSON.parse(new TextDecoder().decode(data));
      return { valid: true };
    } catch (e) {
      return { valid: false, error: 'Invalid artifact format' };
    }
  }

  private async cacheArtifact(
    digest: string,
    data: Uint8Array,
    manifest: BuildManifest
  ): Promise<void> {
    await this.store.put(digest, data);
    const manifestBytes = new TextEncoder().encode(JSON.stringify(manifest));
    await this.store.put(`${digest}.manifest`, manifestBytes);
  }

  private guessArtifactType(ref: string): BuildManifest['type'] {
    if (ref.includes('rootfs')) return 'rootfs';
    if (ref.includes('kernel')) return 'kernel';
    if (ref.includes('runtime')) return 'runtime';
    return 'nix-store';
  }

  private log(message: string): void {
    this.logs.push(message);
    console.log(`[builder] ${message}`);
  }

  private notifyProgress(progress: BuildProgress): void {
    this.progressListeners.forEach(listener => listener(progress));
  }

  onProgress(callback: (progress: BuildProgress) => void): void {
    this.progressListeners.push(callback);
  }

  async clearCache(): Promise<void> {
    await this.store.clearCache();
    this.log('Cache cleared');
  }

  async getStats(): Promise<{ count: number; size: number }> {
    const listResult = await this.store.store.list();
    if (!listResult.ok) {
      return { count: 0, size: 0 };
    }

    let totalSize = 0;
    for (const digest of listResult.value) {
      const result = await this.store.store.get(digest);
      if (result.ok) {
        totalSize += result.value.length;
      }
    }

    return { count: listResult.value.length, size: totalSize };
  }
}
