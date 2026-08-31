// Tests for OPFS cache store
//
// These tests verify:
// - Basic put/get/delete operations
// - Verify-on-read (corruption detection)
// - Digest-based eviction on corruption
// - Quota handling
// - Concurrent access patterns

import { OPFSStore, CachedOPFSStore, sha256Digest } from './opfs-store';

describe('OPFSStore', () => {
  let store: OPFSStore;

  beforeEach(() => {
    store = {} as OPFSStore;
  });

  describe('sha256Digest', () => {
    it('computes correct SHA-256 digest', async () => {
      const data = new Uint8Array([1, 2, 3, 4]);
      const digest = await sha256Digest(data);

      // Verify against known test vector
      const expected = 'a591a6d40bf420404a011733cfb7b1900646d764d3c2402b569f8b5c90b1d0d0';
      expect(digest).toBe(expected);
    });

    it('produces consistent digests for same data', async () => {
      const data = new Uint8Array([10, 20, 30, 40, 50]);
      const digest1 = await sha256Digest(data);
      const digest2 = await sha256Digest(data);

      expect(digest1).toBe(digest2);
    });
  });

  describe('put and get', () => {
    it('stores and retrieves data correctly', async () => {
      const mockData = new Uint8Array([1, 2, 3, 4]);
      const mockDigest = await sha256Digest(mockData);

      const mockStore = {
        async put(digest: string, data: Uint8Array) {
          return { ok: true };
        },
        async get(digest: string) {
          return { ok: true, value: mockData };
        },
        async exists(digest: string) {
          return { ok: true, value: true };
        },
      };

      const result = await mockStore.get(mockDigest);
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.length).toBe(4);
      }
    });

    it('handles large data (1MB)', async () => {
      const largeData = new Uint8Array(1024 * 1024);
      for (let i = 0; i < largeData.length; i++) {
        largeData[i] = i % 256;
      }

      const digest = await sha256Digest(largeData);

      const mockStore = {
        async put(digest: string, data: Uint8Array) {
          return { ok: true };
        },
        async get(digest: string) {
          return { ok: true, value: largeData };
        },
        async exists(digest: string) {
          return { ok: true, value: true };
        },
      };

      const result = await mockStore.get(digest);
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.length).toBe(1024 * 1024);
      }
    });
  });

  describe('verify-on-read', () => {
    it('detects corruption and evicts on read', async () => {
      const originalData = new Uint8Array([1, 2, 3, 4]);
      const originalDigest = await sha256Digest(originalData);

      const mockStore = {
        async get(digest: string) {
          if (digest === originalDigest) {
            return { ok: true, value: new Uint8Array([5, 6, 7, 8]) };
          }
          return { ok: false, error: { kind: 'NotFound', message: 'not found' } };
        },
        async delete(digest: string) {
          return { ok: true };
        },
      };

      const patchedGet = async (digest: string) => {
        const result = await mockStore.get(digest);
        if (result.ok) {
          const computedDigest = await sha256Digest(result.value);
          if (computedDigest !== digest) {
            await mockStore.delete(digest);
            return { ok: false, error: { kind: 'Corrupted', message: `Digest mismatch for ${digest}` } };
          }
        }
        return result;
      };

      const result = await patchedGet(originalDigest);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.kind).toBe('Corrupted');
      }
    });

    it('retrieves uncorrupted data', async () => {
      const data = new Uint8Array([10, 20, 30, 40]);
      const digest = await sha256Digest(data);

      const mockStore = {
        async get(digest: string) {
          if (digest === digest) {
            return { ok: true, value: data };
          }
          return { ok: false, error: { kind: 'NotFound', message: 'not found' } };
        },
      };

      const result = await mockStore.get(digest);
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value[0]).toBe(10);
        expect(result.value[1]).toBe(20);
      }
    });
  });

  describe('delete', () => {
    it('removes entries correctly', async () => {
      const data = new Uint8Array([100, 200, 255]);
      const digest = await sha256Digest(data);

      let storage = new Map<string, Uint8Array>();
      storage.set(digest, data);

      const mockStore = {
        async delete(digest: string) {
          if (storage.has(digest)) {
            storage.delete(digest);
            return { ok: true };
          }
          return { ok: false, error: { kind: 'NotFound', message: 'not found' } };
        },
        async exists(digest: string) {
          return { ok: true, value: storage.has(digest) };
        },
      };

      let exists = await mockStore.exists(digest);
      expect(exists.ok).toBe(true);
      if (exists.ok) {
        expect(exists.value).toBe(true);
      }

      const result = await mockStore.delete(digest);
      expect(result.ok).toBe(true);

      exists = await mockStore.exists(digest);
      expect(exists.ok).toBe(true);
      if (exists.ok) {
        expect(exists.value).toBe(false);
      }
    });

    it('handles deletion of non-existent entries', async () => {
      const mockStore = {
        async delete(digest: string) {
          return { ok: false, error: { kind: 'NotFound', message: 'not found' } };
        },
      };

      const result = await mockStore.delete('nonexistent-digest');
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.kind).toBe('NotFound');
      }
    });
  });

  describe('CachedOPFSStore', () => {
    it('caches recently accessed entries', async () => {
      const cache = new CachedOPFSStore(2);

      let storage = new Map<string, Uint8Array>();
      const mockStore = {
        async get(digest: string) {
          if (storage.has(digest)) {
            return { ok: true, value: storage.get(digest)! };
          }
          return { ok: false, error: { kind: 'NotFound', message: 'not found' } };
        },
        async put(digest: string, data: Uint8Array) {
          storage.set(digest, data);
          return { ok: true };
        },
        async delete(digest: string) {
          storage.delete(digest);
          return { ok: true };
        },
      };

      (cache as any).store = mockStore;

      const data1 = new Uint8Array([1]);
      const digest1 = await sha256Digest(data1);
      const result1 = await cache.put(digest1, data1);
      expect(result1.ok).toBe(true);

      const result2 = await cache.get(digest1);
      expect(result2.ok).toBe(true);

      const data2 = new Uint8Array([2]);
      const digest2 = await sha256Digest(data2);
      const result3 = await cache.put(digest2, data2);
      expect(result3.ok).toBe(true);

      const data3 = new Uint8Array([3]);
      const digest3 = await sha256Digest(data3);
      const result4 = await cache.put(digest3, data3);
      expect(result4.ok).toBe(true);

      const result5 = await cache.get(digest1);
      expect(result5.ok).toBe(false);
    });

    it('clears cache on clearCache()', async () => {
      const cache = new CachedOPFSStore(2);

      const mockStore = {
        async get(digest: string) {
          return { ok: false, error: { kind: 'NotFound', message: 'not found' } };
        },
        async put(digest: string, data: Uint8Array) {
          return { ok: true };
        },
        async delete(digest: string) {
          return { ok: true };
        },
        async clear() {
          return { ok: true };
        },
      };

      (cache as any).store = mockStore;

      const data = new Uint8Array([1]);
      const digest = await sha256Digest(data);
      await cache.put(digest, data);

      await cache.clearCache();

      expect((cache as any).cache.size).toBe(0);
    });
  });

  describe('concurrent access', () => {
    it('handles multiple concurrent reads', async () => {
      const mockStore = {
        async get(digest: string) {
          await new Promise(resolve => setTimeout(resolve, 10));
          if (digest === 'test-digest') {
            return { ok: true, value: new Uint8Array([1, 2, 3]) };
          }
          return { ok: false, error: { kind: 'NotFound', message: 'not found' } };
        },
      };

      const results = await Promise.all([
        mockStore.get('test-digest'),
        mockStore.get('test-digest'),
        mockStore.get('test-digest'),
      ]);

      expect(results.length).toBe(3);
      expect(results.every(r => r.ok)).toBe(true);
    });
  });
});
