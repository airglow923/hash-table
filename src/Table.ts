import Assert from './Assert.js';
import {H1, H2, Hash} from './Hash.js';

type CopyKeyValueType = (s: Buffer, sO: number, t: Buffer, tO: number) => void;

// Slot lookup table, given 8-bits, return the index of an empty slot (if any):
// We use this to find an empty slot in a single branch.
let SLOT = ((): Uint8Array => {
  let slots = 8;
  let table = new Uint8Array(1 << slots);
  for (let index = 0; index < table.length; index++) {
    let slot = 0;
    for (; slot < slots; slot++) {
      if ((index & (1 << slot)) === 0) break;
    }
    table[index] = slot;
  }
  return table;
})();

export default class Table {
  public keySize: number;
  public valueSize: number;
  public bucket: number;
  public buckets: number;
  public copyKey: CopyKeyValueType;
  public copyValue: CopyKeyValueType;
  public mask: number;
  public SLOT: Uint8Array;
  public buffer: Buffer;

  constructor(
    keySize: number,
    valueSize: number,
    bucket: number,
    buckets: number
  ) {
    this.keySize = keySize;
    this.valueSize = valueSize;
    this.bucket = bucket;
    this.buckets = buckets;
    this.buffer = Buffer.alloc(this.bucket * this.buckets);
    // Reduce branching through unrolled copy methods:
    this.copyKey = this.copy(keySize) || this.copyKeyGeneric;
    this.copyValue = this.copy(valueSize) || this.copyValueGeneric;
    // Replace modulus with fast bitwise AND (buckets must be a power of 2):
    this.mask = this.buckets - 1;
    // Optimize global letiable lookup:
    this.SLOT = SLOT;
  }

  public assign(
    bucket: number,
    tag: number,
    slot: number,
    key: Buffer,
    keyOffset: number,
    value: Buffer,
    valueOffset: number
  ): void {
    this.buffer[bucket + 9] |= (1 << slot); // Mark the slot as present.
    this.buffer[bucket + 9 + 1 + slot] = tag; // Assign the element's tag.
    this.copyKey(key, keyOffset, this.buffer, this.keyOffset(bucket, slot));
    this.copyValue(
      value,
      valueOffset,
      this.buffer,
      this.valueOffset(bucket, slot)
    );
  }

  public cache(
    h1: number,
    // @ts-ignore
    h2: number,
    key: Buffer,
    keyOffset: number,
    value: Buffer,
    valueOffset: number
  ): number {
    // See comments in set():
    let tag = (h1 >> 16) & 255;
    let b1 = (h1 & this.mask) * this.bucket;
    let f1 = (tag >> 4) & 7;
    let f2 = 1 << (tag & 7);
    if (this.buffer[b1 + f1] & f2) {
      let s1 = this.scan(b1, tag, key, keyOffset);
      if (s1 < 8) {
        // Mark the element as recently used:
        this.buffer[b1 + 18] |= (1 << s1);
        this.copyValue(value, valueOffset, this.buffer, this.valueOffset(b1, s1));
        return 1;
      }
    }
    // Evict the least recently used slot in first position:
    let s3 = this.evict(b1);
    let eviction = this.buffer[b1 + 9] & (1 << s3);
    if (eviction) {
      // Mark the slot as empty so that the element is excluded from its filter:
      this.buffer[b1 + 9] &= ~(1 << s3);
      // Reset the old element's filter:
      this.filterReset(b1, this.buffer[b1 + 9 + 1 + s3] & 7);
    }
    // Add the new element in its place:
    this.assign(b1, tag, s3, key, keyOffset, value, valueOffset);
    // Add the new element to its filter (this can be a different filter):
    this.buffer[b1 + f1] |= f2;
    // Mark the element as recently used:
    this.buffer[b1 + 18] |= (1 << s3);
    return eviction ? 2 : 0;
  }

  public copy(size: number): CopyKeyValueType | undefined {
    switch (size) {
    case   0: return this.copy00;
    case   4: return this.copy04;
    case   8: return this.copy08;
    case  16: return this.copy16;
    case  20: return this.copy20;
    case  32: return this.copy32;
    case  48: return this.copy48;
    case  64: return this.copy64;
    case 128: return this.copy128;
    case 256: return this.copy256;
    }
    return undefined;
  }

  public copyKeyGeneric(s: Buffer, sO: number, t: Buffer, tO: number): void {
    let size = this.keySize;
    let groups = size >>> 2;
    while (groups--) {
      t[tO + 0] = s[sO + 0];
      t[tO + 1] = s[sO + 1];
      t[tO + 2] = s[sO + 2];
      t[tO + 3] = s[sO + 3];
      tO += 4;
      sO += 4;
      size -= 4;
    }
    while (size--) t[tO++] = s[sO++];
  }

  public copyValueGeneric(s: Buffer, sO: number, t: Buffer, tO: number): void {
    let size = this.valueSize;
    if (size < 128) {
      let groups = size >>> 3;
      while (groups--) {
        t[tO + 0] = s[sO + 0];
        t[tO + 1] = s[sO + 1];
        t[tO + 2] = s[sO + 2];
        t[tO + 3] = s[sO + 3];
        t[tO + 4] = s[sO + 4];
        t[tO + 5] = s[sO + 5];
        t[tO + 6] = s[sO + 6];
        t[tO + 7] = s[sO + 7];
        tO += 8;
        sO += 8;
        size -= 8;
      }
      while (size--) t[tO++] = s[sO++];
    } else {
      s.copy(t, tO, sO, sO + size);
    }
  }

  // @ts-ignore
  public copy00(s: Buffer, sO: number, t: Buffer, tO: number): void {}

  public copy04(s: Buffer, sO: number, t: Buffer, tO: number): void {
    t[tO +  0] = s[sO +  0];
    t[tO +  1] = s[sO +  1];
    t[tO +  2] = s[sO +  2];
    t[tO +  3] = s[sO +  3];
  }

  public copy08(s: Buffer, sO: number, t: Buffer, tO: number): void {
    t[tO +  0] = s[sO +  0];
    t[tO +  1] = s[sO +  1];
    t[tO +  2] = s[sO +  2];
    t[tO +  3] = s[sO +  3];
    t[tO +  4] = s[sO +  4];
    t[tO +  5] = s[sO +  5];
    t[tO +  6] = s[sO +  6];
    t[tO +  7] = s[sO +  7];
  }

  public copy16(s: Buffer, sO: number, t: Buffer, tO: number): void {
    t[tO +  0] = s[sO +  0];
    t[tO +  1] = s[sO +  1];
    t[tO +  2] = s[sO +  2];
    t[tO +  3] = s[sO +  3];
    t[tO +  4] = s[sO +  4];
    t[tO +  5] = s[sO +  5];
    t[tO +  6] = s[sO +  6];
    t[tO +  7] = s[sO +  7];
    t[tO +  8] = s[sO +  8];
    t[tO +  9] = s[sO +  9];
    t[tO + 10] = s[sO + 10];
    t[tO + 11] = s[sO + 11];
    t[tO + 12] = s[sO + 12];
    t[tO + 13] = s[sO + 13];
    t[tO + 14] = s[sO + 14];
    t[tO + 15] = s[sO + 15];
  }

  public copy20 = function(s: Buffer, sO: number, t: Buffer, tO: number): void {
    t[tO +  0] = s[sO +  0];
    t[tO +  1] = s[sO +  1];
    t[tO +  2] = s[sO +  2];
    t[tO +  3] = s[sO +  3];
    t[tO +  4] = s[sO +  4];
    t[tO +  5] = s[sO +  5];
    t[tO +  6] = s[sO +  6];
    t[tO +  7] = s[sO +  7];
    t[tO +  8] = s[sO +  8];
    t[tO +  9] = s[sO +  9];
    t[tO + 10] = s[sO + 10];
    t[tO + 11] = s[sO + 11];
    t[tO + 12] = s[sO + 12];
    t[tO + 13] = s[sO + 13];
    t[tO + 14] = s[sO + 14];
    t[tO + 15] = s[sO + 15];
    t[tO + 16] = s[sO + 16];
    t[tO + 17] = s[sO + 17];
    t[tO + 18] = s[sO + 18];
    t[tO + 19] = s[sO + 19];
  }

  public copy32(s: Buffer, sO: number, t: Buffer, tO: number): void {
    t[tO +  0] = s[sO +  0];
    t[tO +  1] = s[sO +  1];
    t[tO +  2] = s[sO +  2];
    t[tO +  3] = s[sO +  3];
    t[tO +  4] = s[sO +  4];
    t[tO +  5] = s[sO +  5];
    t[tO +  6] = s[sO +  6];
    t[tO +  7] = s[sO +  7];
    t[tO +  8] = s[sO +  8];
    t[tO +  9] = s[sO +  9];
    t[tO + 10] = s[sO + 10];
    t[tO + 11] = s[sO + 11];
    t[tO + 12] = s[sO + 12];
    t[tO + 13] = s[sO + 13];
    t[tO + 14] = s[sO + 14];
    t[tO + 15] = s[sO + 15];
    t[tO + 16] = s[sO + 16];
    t[tO + 17] = s[sO + 17];
    t[tO + 18] = s[sO + 18];
    t[tO + 19] = s[sO + 19];
    t[tO + 20] = s[sO + 20];
    t[tO + 21] = s[sO + 21];
    t[tO + 22] = s[sO + 22];
    t[tO + 23] = s[sO + 23];
    t[tO + 24] = s[sO + 24];
    t[tO + 25] = s[sO + 25];
    t[tO + 26] = s[sO + 26];
    t[tO + 27] = s[sO + 27];
    t[tO + 28] = s[sO + 28];
    t[tO + 29] = s[sO + 29];
    t[tO + 30] = s[sO + 30];
    t[tO + 31] = s[sO + 31];
  }

  public copy48(s: Buffer, sO: number, t: Buffer, tO: number): void {
    this.copy32(s, sO +  0, t, tO +  0);
    this.copy16(s, sO + 32, t, tO + 32);
  }

  public copy64(s: Buffer, sO: number, t: Buffer, tO: number): void {
    this.copy32(s, sO +  0, t, tO +  0);
    this.copy32(s, sO + 32, t, tO + 32);
  }

  public copy128(s: Buffer, sO: number, t: Buffer, tO: number): void {
    this.copy32(s, sO +  0, t, tO +  0);
    this.copy32(s, sO + 32, t, tO + 32);
    this.copy32(s, sO + 64, t, tO + 64);
    this.copy32(s, sO + 96, t, tO + 96);
  }

  public copy256(s: Buffer, sO: number, t: Buffer, tO: number): void {
    this.copy32(s, sO +   0, t, tO +   0);
    this.copy32(s, sO +  32, t, tO +  32);
    this.copy32(s, sO +  64, t, tO +  64);
    this.copy32(s, sO +  96, t, tO +  96);
    this.copy32(s, sO + 128, t, tO + 128);
    this.copy32(s, sO + 160, t, tO + 160);
    this.copy32(s, sO + 192, t, tO + 192);
    this.copy32(s, sO + 224, t, tO + 224);
  }

  public equal(
    a: Buffer,
    aOffset: number,
    b: Buffer,
    bOffset: number,
    size: number
  ): number {
    while (size--) {
      if (a[aOffset++] != b[bOffset++]) return 0;
    }
    return 1;
  }

  // Evict an element using the CLOCK eviction policy which approximates LRU:
  public evict(bucket: number): any {
    // After the CLOCK hand wraps, we are guaranteed an eviction:
    let tick = 8 + 1;
    let slot;

    while (tick--) {
      // Find the slot pointed to by CLOCK hand:
       slot = this.buffer[bucket + 18 + 1];
      // Increment CLOCK hand regardless of whether slot was recently used:
      this.buffer[bucket + 18 + 1] = (this.buffer[bucket + 18 + 1] + 1) & 7;
      // Evict slot if slot was not recently used:
      if ((this.buffer[bucket + 18] & (1 << slot)) === 0) break;
      // Slot was recently used, clear recently used bit and keep ticking:
      this.buffer[bucket + 18] &= ~(1 << slot);
    }
    return slot;
  }

  public exist(h1: number, h2: number, key: Buffer, keyOffset: number): number {
    // See comments in set():
    let tag = (h1 >> 16) & 255;
    let b1 = (h1 & this.mask) * this.bucket;
    let b2 = (h2 & this.mask) * this.bucket;
    let f1 = (tag >> 4) & 7;
    let f2 = 1 << (tag & 7);
    if (this.buffer[b1 + f1] & f2) {
      let s1 = this.scan(b1, tag, key, keyOffset);
      if (s1 < 8) return 1;
      let s2 = this.scan(b2, tag, key, keyOffset);
      if (s2 < 8) return 1;
    }
    return 0;
  }

  // Decrement a filter's count of elements in second position:
  public filterDecrementSecondPosition(bucket: number): void {
    if (this.buffer[bucket + 8] === 0) throw new Error('count should not be 0');
    if (this.buffer[bucket + 8] < 255) {
      this.buffer[bucket + 8]--;
      if (this.buffer[bucket + 8] === 0) {
        for (let filter = 0; filter < 8; filter++) {
          this.filterReset(bucket, filter);
        }
      }
    }
  }

  // Increment a filter's count of elements in second position:
  public filterIncrementSecondPosition(bucket: number): void {
    // Once the counter saturates, it can no longer be incremented or decremented.
    // This is extremely unlikely, we expect at most 4 elements and can count 254.
    // Even if it does saturate, the worst is that we never reset the filter.
    if (this.buffer[bucket + 8] < 255) {
      this.buffer[bucket + 8]++;
    }
  }

  // Reset a filter to remove stale entries:
  public filterReset(bucket: number, filter: number): void {
    // Filter has elements in second position and cannot be reset:
    if (this.buffer[bucket + 8] !== 0) return;
    // Filter has no elements (since no bits are set):
    if (this.buffer[bucket + filter] === 0) return;
    // Reset filter and add elements back:
    this.buffer[bucket + filter] = 0;
    for (let slot = 0; slot < 8; slot++) {
      // Slot must be present (not empty):
      if (this.buffer[bucket + 9] & (1 << slot)) {
        // Element must belong to the same filter (and be in first position):
        // We do not check whether element is actually in second position.
        // This would need special bookkeeping, is unlikely, and adds little.
        let tag = this.buffer[bucket + 9 + 1 + slot];
        let f1 = (tag >> 4) & 7;
        if (f1 === filter) {
          let f2 = 1 << (tag & 7);
          this.buffer[bucket + filter] |= f2;
        }
      }
    }
  }

  public get(
    h1: number,
    h2: number,
    key: Buffer,
    keyOffset: number,
    value: Buffer,
    valueOffset: number
  ): number {
    // See comments in set():
    let tag = (h1 >> 16) & 255;
    let b1 = (h1 & this.mask) * this.bucket;
    let b2 = (h2 & this.mask) * this.bucket;
    let f1 = (tag >> 4) & 7;
    let f2 = 1 << (tag & 7);
    if (this.buffer[b1 + f1] & f2) {
      let s1 = this.scan(b1, tag, key, keyOffset);
      if (s1 < 8) {
        // Mark element as recently used:
        this.buffer[b1 + 18] |= (1 << s1);
        this.copyValue(this.buffer, this.valueOffset(b1, s1), value, valueOffset);
        return 1;
      }
      let s2 = this.scan(b2, tag, key, keyOffset);
      if (s2 < 8) {
        this.buffer[b2 + 18] |= (1 << s2);
        this.copyValue(this.buffer, this.valueOffset(b2, s2), value, valueOffset);
        return 1;
      }
    }
    return 0;
  }

  public keyOffset(bucket: number, slot: number): number {
    // 20 = 8:Filter 1:FilterCount 1:Present 8:Tags 1:ClockUsed 1:ClockHand
    // We keep the element's key and value together to optimize the common case of
    // comparing the key and retrieving the value without a cache miss.
    return bucket + 20 + (this.keySize + this.valueSize) * slot;
  }

  public resize(resizeBuckets: number): number {
    Assert.GE('resizeBuckets', resizeBuckets, this.buckets * 2);
    Assert.P2('resizeBuckets', resizeBuckets);
    if (
      resizeBuckets > HashTable.BUCKETS_MAX ||
      this.bucket * resizeBuckets > HashTable.BUFFER_MAX
    ) {
      throw new Error(HashTable.ERROR_MAXIMUM_CAPACITY_EXCEEDED);
    }
    let buckets = this.buckets;
    let buffer = this.buffer;
    this.buckets = resizeBuckets;
    this.buffer = Buffer.alloc(this.bucket * resizeBuckets);
    this.mask = resizeBuckets - 1;
    for (let index = 0; index < buckets; index++) {
      let bucket = index * this.bucket;
      for (let slot = 0; slot < 8; slot++) {
        if (buffer[bucket + 9] & (1 << slot)) {
          // We assume keyOffset, valueOffset depend only on bucket and slot:
          let keyOffset = this.keyOffset(bucket, slot);
          let valueOffset = this.valueOffset(bucket, slot);
          Hash(buffer, keyOffset, this.keySize);
          if (this.set(H1, H2, buffer, keyOffset, buffer, valueOffset) === -1) {
            // Fail this resize() attempt (and restore back to before resize):
            // The caller should try again with more resizeBuckets.
            this.buckets = buckets;
            this.buffer = buffer;
            this.mask = buckets - 1;
            return 0;
          }
        }
      }
    }
    return 1;
  }

  public scan(
    bucket: number,
    tag: number,
    key: Buffer,
    keyOffset: number
  ): number {
    let slot = 0;
    for (; slot < 8; slot++) {
      if (
        // Check the tag before checking presence bits:
        // The tag is a better branch predictor with more entropy.
        (this.buffer[bucket + 9 + 1 + slot] === tag) &&
        (this.buffer[bucket + 9] & (1 << slot)) &&
        this.equal(
          this.buffer,
          this.keyOffset(bucket, slot),
          key,
          keyOffset,
          this.keySize
        )
      ) {
        break;
      }
    }
    return slot;
  }

  public set(
    h1: number,
    h2: number,
    key: Buffer,
    keyOffset: number,
    value: Buffer,
    valueOffset: number
  ): number {
    // Use the 2nd most significant byte of H1 for 1-byte tag:
    let tag = (h1 >> 16) & 255;
    // Use the 3rd and 4th most significant bytes of H1 and H2 for bucket offset:
    let b1 = (h1 & this.mask) * this.bucket;
    let b2 = (h2 & this.mask) * this.bucket;
    // Reuse tag entropy for filter entropy (instead of using 2nd MSB from H2):
    // This enables us to find the filter for any element without hashing its key.
    // This increases tag-scanning false positives, but optimizes filter resets.
    // This tradeoff is significant for cache(), where evictions reset filters.
    // At 100% occupancy, 1 element per filter, we expect 1 in 9 false positives.
    // See: https://hur.st/bloomfilter/?n=1&p=&m=8&k=1
    let f1 = (tag >> 4) & 7; // Use tag's upper 4-bits to select a 1-byte filter.
    let f2 = 1 << (tag & 7); // Use tag's lower 4-bits to select a bit.
    // Check the filter to see if the element might exist:
    if (this.buffer[b1 + f1] & f2) {
      // Search for the element and update the element's value if found:
      let s1 = this.scan(b1, tag, key, keyOffset);
      if (s1 < 8) {
        this.copyValue(value, valueOffset, this.buffer, this.valueOffset(b1, s1));
        return 1;
      }
      let s2 = this.scan(b2, tag, key, keyOffset);
      if (s2 < 8) {
        this.copyValue(value, valueOffset, this.buffer, this.valueOffset(b2, s2));
        return 1;
      }
    }
    // Find an empty slot in first position:
    let s3 = this.SLOT[this.buffer[b1 + 9]];
    if (s3 < 8) {
      this.assign(b1, tag, s3, key, keyOffset, value, valueOffset);
      this.buffer[b1 + f1] |= f2;
      return 0;
    }
    // Find an empty slot in second position:
    let s4 = this.SLOT[this.buffer[b2 + 9]];
    if (s4 < 8) {
      this.assign(b2, tag, s4, key, keyOffset, value, valueOffset);
      this.buffer[b1 + f1] |= f2;
      this.filterIncrementSecondPosition(b1);
      return 0;
    }
    // Vacate a slot in first position:
    let s5 = this.vacate(b1);
    if (s5 < 8) {
      this.assign(b1, tag, s5, key, keyOffset, value, valueOffset);
      this.buffer[b1 + f1] |= f2;
      return 0;
    }
    // Vacate a slot in second position:
    let s6 = this.vacate(b2);
    if (s6 < 8) {
      this.assign(b2, tag, s6, key, keyOffset, value, valueOffset);
      this.buffer[b1 + f1] |= f2;
      this.filterIncrementSecondPosition(b1);
      return 0;
    }
    return -1;
  }

  public unset(h1: number, h2: number, key: Buffer, keyOffset: number): number {
    // See comments in set():
    let tag = (h1 >> 16) & 255;
    let b1 = (h1 & this.mask) * this.bucket;
    let b2 = (h2 & this.mask) * this.bucket;
    let f1 = (tag >> 4) & 7;
    let f2 = 1 << (tag & 7);
    if (this.buffer[b1 + f1] & f2) {
      let s1 = this.scan(b1, tag, key, keyOffset);
      if (s1 < 8) {
        this.buffer[b1 + 9] &= ~(1 << s1);
        this.buffer[b1 + 9 + 1 + s1] = 0;
        this.zero(this.keyOffset(b1, s1), this.keySize);
        this.zero(this.valueOffset(b1, s1), this.valueSize);
        this.filterReset(b1, f1);
        return 1;
      }
      let s2 = this.scan(b2, tag, key, keyOffset);
      if (s2 < 8) {
        this.buffer[b2 + 9] &= ~(1 << s2);
        this.buffer[b2 + 9 + 1 + s2] = 0;
        this.zero(this.keyOffset(b2, s2), this.keySize);
        this.zero(this.valueOffset(b2, s2), this.valueSize);
        this.filterDecrementSecondPosition(b1);
        return 1;
      }
    }
    return 0;
  }

  public vacate(bucket: number): number {
    let slot = 0;
    for (; slot < 8; slot++) {
      let keyOffset = this.keyOffset(bucket, slot);
      let valueOffset = this.valueOffset(bucket, slot);
      Hash(this.buffer, keyOffset, this.keySize);
      let tag = (H1 >> 16) & 255;
      let b1 = (H1 & this.mask) * this.bucket;
      let b2 = (H2 & this.mask) * this.bucket;
      if (bucket === b1) {
        // Move existing element to second position if there is an empty slot:
        let s2 = this.SLOT[this.buffer[b2 + 9]];
        if (s2 < 8) {
          this.assign(
            b2, tag, s2, this.buffer, keyOffset, this.buffer, valueOffset
          );
          this.filterIncrementSecondPosition(b1);
          break;
        }
        // First and second positions are the same, or second position is full.
      } else if (bucket === b2) {
        // Move existing element back to first position if there is an empty slot:
        let s1 = this.SLOT[this.buffer[b1 + 9]];
        if (s1 < 8) {
          this.assign(
            b1, tag, s1, this.buffer, keyOffset, this.buffer, valueOffset
          );
          this.filterDecrementSecondPosition(b1);
          break;
        }
      } else {
        throw new Error('bucket !== b1 && bucket !== b2');
      }
    }
    return slot;
  }

  public valueOffset(bucket: number, slot: number): number {
    // See comment in keyOffset():
    return bucket + 20 + (this.keySize + this.valueSize) * slot + this.keySize;
  }

  public zero(offset: number, size: number): void {
    if (size < 64) {
      let groups = size >>> 2;
      while (groups--) {
        this.buffer[offset + 0] = 0;
        this.buffer[offset + 1] = 0;
        this.buffer[offset + 2] = 0;
        this.buffer[offset + 3] = 0;
        offset += 4;
        size -= 4;
      }
      while (size--) this.buffer[offset++] = 0;
    } else {
      this.buffer.fill(0, offset, offset + size);
    }
  }
}
