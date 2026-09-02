// OPFS-backed block file support for WebLinux volumes
//
// Provides random-access block files using OPFS, simulating block devices
// for the WebLinux backend's volume mounts.

import { OPFSStore, sha256Digest, StoreResult } from './opfs-store';

// Block size for volume operations (4KB typical)
export const BLOCK_SIZE = 4096;

export type BlockFileError = {
  kind: 'NotFound' | 'Corrupted' | 'QuotaExceeded' | 'PermissionDenied' | 'InvalidRange' | 'WriteLocked' | 'Other';
  message: string;
};

export type BlockFileResult<T> = {
  ok: true;
  value: T;
} | {
  ok: false;
  error: BlockFileError;
};

/**
 * A block-backed file stored in OPFS
 */
export class BlockFile {
  private store: OPFSStore;
  private digest: string;
  private size: number;
  private writeLocked: boolean;

  constructor(store: OPFSStore, digest: string, size: number) {
    this.store = store;
    this.digest = digest;
    this.size = size;
    this.writeLocked = false;
  }

  /**
   * Create a new block file from data
   */
  static async create(store: OPFSStore, data: Uint8Array): Promise<BlockFile> {
    const digest = await sha256Digest(data);
    const result = await store.put(digest, data);
    if (!result.ok) {
      throw new Error(`Failed to create block file: ${result.error.message}`);
    }

    return new BlockFile(store, digest, data.length);
  }

  /**
   * Open an existing block file
   */
  static async open(store: OPFSStore, digest: string): Promise<BlockFileResult<BlockFile>> {
    const exists = await store.exists(digest);
    if (!exists.ok) {
      return { ok: false, error: { kind: 'Other', message: exists.error.message } };
    }
    if (!exists.value) {
      return { ok: false, error: { kind: 'NotFound', message: `Block file ${digest} not found` } };
    }

    // Get size by fetching the entire file
    const result = await store.get(digest);
    if (!result.ok) {
      return { ok: false, error: { kind: result.error.kind, message: result.error.message } };
    }

    return { ok: true, value: new BlockFile(store, digest, result.value.length) };
  }

  /**
   * Get the size of the file in bytes
   */
  getSize(): number {
    return this.size;
  }

  /**
   * Read data from the file
   */
  async read(offset: number, length: number): Promise<BlockFileResult<Uint8Array>> {
    if (offset < 0 || offset > this.size) {
      return { ok: false, error: { kind: 'InvalidRange', message: `Invalid offset ${offset} for file size ${this.size}` } };
    }

    if (offset + length > this.size) {
      length = this.size - offset;
    }

    const result = await this.store.get(this.digest);
    if (!result.ok) {
      return { ok: false, error: { kind: result.error.kind, message: result.error.message } };
    }

    return { ok: true, value: result.value.slice(offset, offset + length) };
  }

  /**
   * Write data to the file
   */
  async write(data: Uint8Array, offset: number): Promise<BlockFileResult<void>> {
    if (this.writeLocked) {
      return { ok: false, error: { kind: 'WriteLocked', message: 'Block file is write-locked' } };
    }

    if (offset < 0 || offset > this.size) {
      return { ok: false, error: { kind: 'InvalidRange', message: `Invalid offset ${offset} for file size ${this.size}` } };
    }

    // Read existing data
    const existing = await this.read(0, this.size);
    if (!existing.ok) {
      return { ok: false, error: { kind: existing.error.kind, message: existing.error.message } };
    }

    // Create new data
    const newData = new Uint8Array(existing.value.length);
    newData.set(existing.value);
    newData.set(data, offset);

    // Update the file
    const digest = await sha256Digest(newData);
    const result = await this.store.put(digest, newData);
    if (!result.ok) {
      return { ok: false, error: { kind: result.error.kind, message: result.error.message } };
    }

    this.digest = digest;
    this.size = newData.length;

    return { ok: true };
  }

  /**
   * Truncate the file to a new size
   */
  async truncate(newSize: number): Promise<BlockFileResult<void>> {
    if (this.writeLocked) {
      return { ok: false, error: { kind: 'WriteLocked', message: 'Block file is write-locked' } };
    }

    if (newSize < 0) {
      return { ok: false, error: { kind: 'InvalidRange', message: `Invalid size ${newSize}` } };
    }

    // Read existing data
    const existing = await this.read(0, this.size);
    if (!existing.ok) {
      return { ok: false, error: { kind: existing.error.kind, message: existing.error.message } };
    }

    // Create new data (pad with zeros if growing)
    const newData = new Uint8Array(newSize);
    if (existing.value.length > 0) {
      newData.set(existing.value.slice(0, Math.min(existing.value.length, newSize)));
    }

    // Update the file
    const digest = await sha256Digest(newData);
    const result = await this.store.put(digest, newData);
    if (!result.ok) {
      return { ok: false, error: { kind: result.error.kind, message: result.error.message } };
    }

    this.digest = digest;
    this.size = newData.length;

    return { ok: true };
  }

  /**
   * Lock the file for writing (to enforce single-writer semantics)
   */
  lockWrite(): void {
    this.writeLocked = true;
  }

  /**
   * Unlock the file for writing
   */
  unlockWrite(): void {
    this.writeLocked = false;
  }

  /**
   * Check if the file is write-locked
   */
  isWriteLocked(): boolean {
    return this.writeLocked;
  }

  /**
   * Get the file's content digest
   */
  getDigest(): string {
    return this.digest;
  }

  /**
   * Close the file (release resources)
   */
  close(): void {
    // No resources to release (OPFS handles are stream-based)
  }
}

/**
 * A block device that uses OPFS for storage
 */
export class OPFSBlockDevice {
  private store: OPFSStore;
  private files: Map<string, BlockFile> = new Map();

  constructor(store: OPFSStore) {
    this.store = store;
  }

  /**
   * Create a new block device file
   */
  async createFile(size: number): Promise<BlockFileResult<string>> {
    const data = new Uint8Array(size);
    const file = await BlockFile.create(this.store, data);
    this.files.set(file.getDigest(), file);
    return { ok: true, value: file.getDigest() };
  }

  /**
   * Open an existing block device file
   */
  async openFile(digest: string): Promise<BlockFileResult<BlockFile>> {
    const file = await BlockFile.open(this.store, digest);
    if (file.ok) {
      this.files.set(file.value.getDigest(), file.value);
    }
    return file;
  }

  /**
   * Delete a block device file
   */
  async deleteFile(digest: string): Promise<BlockFileResult<void>> {
    const file = this.files.get(digest);
    if (file) {
      file.close();
      this.files.delete(digest);
    }

    return this.store.delete(digest);
  }

  /**
   * List all block device files
   */
  async listFiles(): Promise<BlockFileResult<string[]>> {
    return this.store.list();
  }

  async clearFile(): Promise<BlockFileResult<void>> {
    const listResult = await this.listFiles();
    if (!listResult.ok) {
      return { ok: false, error: { kind: listResult.error.kind, message: listResult.error.message } };
    }

    for (const digest of listResult.value) {
      await this.deleteFile(digest);
    }

    return { ok: true };
  }

  /**
   * Get usage information
   */
  async getUsage(): Promise<BlockFileResult<{ used: number; quota: number }>> {
    return this.store.getUsage();
  }
}
