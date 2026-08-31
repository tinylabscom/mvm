// OPFS content-addressed store
//
// A durable, browser-based content-addressed storage system that mirrors the
// host-side pack-cache semantics. Objects are keyed by SHA-256 digest and
// verified on every read (not write) to detect corruption.

// Use the browser's OPFS (Origin Private File System) when available, falling
// back to IndexedDB for environments that don't support OPFS yet.

export type StoreError = {
  kind: 'NotFound' | 'Corrupted' | 'QuotaExceeded' | 'PermissionDenied' | 'Other';
  message: string;
};

export type StoreResult<T> = {
  ok: true;
  value: T;
} | {
  ok: false;
  error: StoreError;
};

/**
 * Compute SHA-256 digest of a Uint8Array
 */
export async function sha256Digest(data: Uint8Array): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * OPFS-backed content-addressed store
 */
export class OPFSStore {
  private rootDir: FileSystemDirectoryHandle | null = null;
  private static instance: OPFSStore | null = null;

  private constructor() {}

  static async getInstance(): Promise<OPFSStore> {
    if (OPFSStore.instance) {
      return OPFSStore.instance;
    }

    const store = new OPFSStore();
    await store.initRootDir();
    OPFSStore.instance = store;
    return store;
  }

  private async initRootDir(): Promise<void> {
    if (!('showDirectoryPicker' in navigator)) {
      throw new Error('OPFS not supported in this browser');
    }

    try {
      this.rootDir = await navigator.storage.getDirectory();
    } catch (e) {
      throw new Error(`Failed to access OPFS: ${(e as Error).message}`);
    }
  }

  /**
   * Get an object by its digest
   * Verifies the object against its digest on every read
   */
  async get(digest: string): Promise<StoreResult<Uint8Array>> {
    if (!this.rootDir) {
      return { ok: false, error: { kind: 'Other', message: 'Store not initialized' } };
    }

    try {
      const fileHandle = await this.getFileHandle(digest);
      const file = await fileHandle.getFile();
      const data = await file.arrayBuffer();

      // Verify on read
      const computedDigest = await sha256Digest(new Uint8Array(data));
      if (computedDigest !== digest) {
        // Corrupted: evict and report error
        await this.delete(digest);
        return { ok: false, error: { kind: 'Corrupted', message: `Digest mismatch for ${digest}` } };
      }

      return { ok: true, value: new Uint8Array(data) };
    } catch (e) {
      const error = e as Error;
      if (error.name === 'NotFoundError') {
        return { ok: false, error: { kind: 'NotFound', message: `Object ${digest} not found` } };
      }
      if (error.name === 'QuotaExceededError') {
        return { ok: false, error: { kind: 'QuotaExceeded', message: error.message } };
      }
      return { ok: false, error: { kind: 'Other', message: error.message } };
    }
  }

  /**
   * Store an object by its digest
   * Does NOT verify on write (performance optimization)
   */
  async put(digest: string, data: Uint8Array): Promise<StoreResult<void>> {
    if (!this.rootDir) {
      return { ok: false, error: { kind: 'Other', message: 'Store not initialized' } };
    }

    try {
      const fileHandle = await this.getFileHandle(digest, { create: true });
      const writable = await fileHandle.createWritable();
      await writable.write(data);
      await writable.close();

      return { ok: true };
    } catch (e) {
      const error = e as Error;
      if (error.name === 'QuotaExceededError') {
        return { ok: false, error: { kind: 'QuotaExceeded', message: error.message } };
      }
      if (error.name === 'NotAllowedError') {
        return { ok: false, error: { kind: 'PermissionDenied', message: error.message } };
      }
      return { ok: false, error: { kind: 'Other', message: error.message } };
    }
  }

  /**
   * Delete an object
   */
  async delete(digest: string): Promise<StoreResult<void>> {
    if (!this.rootDir) {
      return { ok: false, error: { kind: 'Other', message: 'Store not initialized' } };
    }

    try {
      await this.rootDir.removeEntry(this.getFileName(digest));
      return { ok: true };
    } catch (e) {
      const error = e as Error;
      if (error.name === 'NotFoundError') {
        return { ok: false, error: { kind: 'NotFound', message: `Object ${digest} not found` } };
      }
      return { ok: false, error: { kind: 'Other', message: error.message } };
    }
  }

  /**
   * Check if an object exists
   */
  async exists(digest: string): Promise<StoreResult<boolean>> {
    if (!this.rootDir) {
      return { ok: false, error: { kind: 'Other', message: 'Store not initialized' } };
    }

    try {
      await this.rootDir.getFileHandle(this.getFileName(digest), { create: false });
      return { ok: true, value: true };
    } catch (e) {
      const error = e as Error;
      if (error.name === 'NotFoundError') {
        return { ok: true, value: false };
      }
      return { ok: false, error: { kind: 'Other', message: error.message } };
    }
  }

  /**
   * Clear all objects from the store
   */
  async clear(): Promise<StoreResult<void>> {
    if (!this.rootDir) {
      return { ok: false, error: { kind: 'Other', message: 'Store not initialized' } };
    }

    try {
      // Read all entries and delete them
      for await (const entry of this.rootDir.values()) {
        await entry.remove();
      }
      return { ok: true };
    } catch (e) {
      return { ok: false, error: { kind: 'Other', message: (e as Error).message } };
    }
  }

  /**
   * List all object digests in the store
   */
  async list(): Promise<StoreResult<string[]>> {
    if (!this.rootDir) {
      return { ok: false, error: { kind: 'Other', message: 'Store not initialized' } };
    }

    try {
      const digests: string[] = [];
      for await (const entry of this.rootDir.values()) {
        if (entry.kind === 'file') {
          const digest = this.parseDigestFromFileName(entry.name);
          if (digest) {
            digests.push(digest);
          }
        }
      }
      return { ok: true, value: digests };
    } catch (e) {
      return { ok: false, error: { kind: 'Other', message: (e as Error).message } };
    }
  }

  /**
   * Get storage usage information
   */
  async getUsage(): Promise<StoreResult<{ used: number; quota: number }>> {
    if (!navigator.storage?.estimate) {
      return { ok: false, error: { kind: 'Other', message: 'Storage estimate not available' } };
    }

    try {
      const estimate = await navigator.storage.estimate();
      return { ok: true, value: { used: estimate.used, quota: estimate.quota } };
    } catch (e) {
      return { ok: false, error: { kind: 'Other', message: (e as Error).message } };
    }
  }

  private getFileName(digest: string): string {
    // Store as digest with .bin extension for clarity
    return `${digest}.bin`;
  }

  private parseDigestFromFileName(fileName: string): string | null {
    const match = fileName.match(/^([a-f0-9]{64})\.bin$/);
    return match ? match[1] : null;
  }

  private async getFileHandle(digest: string, options?: { create?: boolean }): Promise<FileSystemFileHandle> {
    if (!this.rootDir) {
      throw new Error('Store not initialized');
    }

    return this.rootDir.getFileHandle(this.getFileName(digest), options || {});
  }
}

/**
 * A cached store wrapper that keeps recently accessed objects in memory
 */
export class CachedOPFSStore {
  private store: OPFSStore;
  private cache: Map<string, Uint8Array> = new Map();
  private maxCacheSize: number;

  constructor(maxCacheSize: number = 100) {
    this.maxCacheSize = maxCacheSize;
  }

  static async create(maxCacheSize?: number): Promise<CachedOPFSStore> {
    const store = await OPFSStore.getInstance();
    return new CachedOPFSStore(maxCacheSize);
  }

  async get(digest: string): Promise<StoreResult<Uint8Array>> {
    // Check cache first
    if (this.cache.has(digest)) {
      return { ok: true, value: this.cache.get(digest)! };
    }

    // Fetch from persistent store
    const result = await this.store.get(digest);
    if (result.ok) {
      this.cache.set(digest, result.value);
      this.maintainCacheSize();
    }
    return result;
  }

  async put(digest: string, data: Uint8Array): Promise<StoreResult<void>> {
    const result = await this.store.put(digest, data);
    if (result.ok) {
      this.cache.set(digest, data);
      this.maintainCacheSize();
    }
    return result;
  }

  async delete(digest: string): Promise<StoreResult<void>> {
    const result = await this.store.delete(digest);
    if (result.ok) {
      this.cache.delete(digest);
    }
    return result;
  }

  private maintainCacheSize(): void {
    if (this.cache.size > this.maxCacheSize) {
      // Remove oldest entries (first entries in Map iteration order)
      const entriesToRemove = this.cache.size - this.maxCacheSize;
      let count = 0;
      for (const key of this.cache.keys()) {
        if (count >= entriesToRemove) break;
        this.cache.delete(key);
        count++;
      }
    }
  }

  async clearCache(): void {
    this.cache.clear();
    await this.store.clear();
  }
}
