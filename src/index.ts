// @ts-ignore
import * as crypto from 'crypto';
// @ts-ignore
import * as buffer from 'buffer';

class Assert {
  public static GE(key: string, value: number, bound: number): void {
    if (!Number.isInteger(value)) {
      throw new Error(key + ' must be an integer');
    }

    if (!Number.isInteger(bound)) {
      throw new Error(key + ' bound not an integer');
    }

    if (value < bound) {
      throw new Error(key + ' must be at least ' + bound);
    }
  };

  public static LE(key: string, value: number, bound: number): void {
    if (!Number.isInteger(value)) {
      throw new Error(key + ' must be an integer');
    }

    if (!Number.isInteger(bound)) {
      throw new Error(key + ' bound not an integer');
    }

    if (value > bound) {
      throw new Error(key + ' must be at most ' + bound);
    }
  };

  public static P2(key: string, value: number): void {
    if (!Number.isInteger(value)) {
      throw new Error(key + ' must be an integer');
    }

    if (value <= 0) {
      throw new Error(key + ' must be greater than 0');
    }

    if (value & (value - 1)) {
      throw new Error(key + ' must be a power of 2');
    }
  };
}

// Hashes assigned by Hash() instead of using multiple return destructuring:
// We want to avoid allocating millions of objects just to return 2 hashes.
let H1 = 0;
let H2 = 0;

// Tabulation hash function:
function Hash(key: Buffer, keyOffset: number, keySize: number): void {
  // Assigning to a local variable is faster than to a global variable:
  let h1 = 0;
  let h2 = 0;
  let i = 0;
  while (i < keySize) {
    // Minimize cache misses by interleaving both tables into a single table:
    // Minimize letiable assignments by reusing k as an index into TABLE:
    // Unrolled to process 4 bytes at a time:
    h1 ^= (
      TABLE[(((i << 1) + 0) << 8) + key[keyOffset + i + 0]] ^
      TABLE[(((i << 1) + 1) << 8) + key[keyOffset + i + 1]] ^
      TABLE[(((i << 1) + 2) << 8) + key[keyOffset + i + 2]] ^
      TABLE[(((i << 1) + 3) << 8) + key[keyOffset + i + 3]]
    );
    h2 ^= (
      TABLE[(((i << 1) + 4) << 8) + key[keyOffset + i + 0]] ^
      TABLE[(((i << 1) + 5) << 8) + key[keyOffset + i + 1]] ^
      TABLE[(((i << 1) + 6) << 8) + key[keyOffset + i + 2]] ^
      TABLE[(((i << 1) + 7) << 8) + key[keyOffset + i + 3]]
    );
    i += 4;
  }
  H1 = h1;
  H2 = h2;
}

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

// Interleaved entropy table used by tabulation hash function:
let TABLE = ((): Int32Array => {
  let word = 4;
  let table = new Int32Array(64 * 256 * 2);
  let buffer = crypto.randomBytes(table.length * word);
  for (let index = 0, length = table.length; index < length; index++) {
    table[index] = buffer.readInt32LE(index * word);
  }
  return table;
})();

// A fallback for when valueSize is 0 and the user does not pass a value buffer:
const VALUE: Buffer = Buffer.alloc(0);

export default class HashTable {
  // Constants:
  public static KEY_MIN: number = 4;
  public static KEY_MAX: number = 64;
  public static VALUE_MIN: number = 0;
  public static VALUE_MAX: number = 1048576;
  public static BUFFERS_MIN: number = 1;
  public static BUFFERS_MAX: number = 8192;
  public static ELEMENTS_MIN: number = 0;
  public static ELEMENTS_MAX: number = 4294967296;
  public static BUCKETS_MIN: number = 2;
  public static BUCKETS_MAX: number = 65536;
  public static BUFFER_MAX: number = buffer.kMaxLength;

  // Too many elements or buffer allocation limit reached, add more buffers:
  public static ERROR_MAXIMUM_CAPACITY_EXCEEDED: string = 'maximum capacity exceeded';

  // cache() and set() methods are mutually exclusive:
  // Once cache() is called, the table switches to non-resizing, caching mode.
  // Once set() is called, the table switches to resizing, second position mode.
  // This enables several optimizations and is safer:
  // 1. cache() does not need to scan second position for an element.
  // 2. cache() can assume all elements are in first position when refiltering.
  // 3. cache() might otherwise evict an element that was inserted using set().
  public static ERROR_MODE: string = 'cache() and set() methods are mutually exclusive';

  // This might indicate an adversarial attack, or weak tabulation hash entropy:
  public static ERROR_SET: string = 'set() failed despite multiple resize attempts';

  public keySize: number;
  public valueSize: number;
  public bucket: number;
  public capacity: number;
  public length: number;
  public mask: number;
  public mode: number;
  public tables: Array<Table>;

  constructor(
    keySize: number,
    valueSize: number,
    elementsMin: number = 1024,
    elementsMax: number = 0
  ) {
    Assert.GE('keySize', keySize, HashTable.KEY_MIN);
    Assert.LE('keySize', keySize, HashTable.KEY_MAX);

    // We optimize the hash function significantly given key is a multiple of 4:
    if (keySize % 4) {
      throw new Error('keySize must be a multiple of 4');
    }

    Assert.GE('valueSize', valueSize, HashTable.VALUE_MIN);
    Assert.LE('valueSize', valueSize, HashTable.VALUE_MAX);
    Assert.GE('elementsMin', elementsMin, HashTable.ELEMENTS_MIN);
    Assert.LE('elementsMin', elementsMin, HashTable.ELEMENTS_MAX);

    if (elementsMax === 0) {
      elementsMax = Math.max(elementsMin + 4194304, elementsMin * 1024);
      elementsMax = Math.min(elementsMax, HashTable.ELEMENTS_MAX);
    }

    Assert.GE('elementsMax', elementsMax, 1);
    Assert.GE('elementsMax', elementsMax, elementsMin);
    Assert.LE('elementsMax', elementsMax, HashTable.ELEMENTS_MAX);

    let capacityMin = HashTable.capacity(elementsMin);
    let capacityMax = HashTable.capacity(elementsMax);
    let buffers = HashTable.buffers(keySize, valueSize, capacityMax);

    Assert.GE('buffers', buffers, HashTable.BUFFERS_MIN);
    Assert.LE('buffers', buffers, HashTable.BUFFERS_MAX);
    Assert.P2('buffers', buffers);

    let buckets = HashTable.buckets(capacityMin, buffers);

    if (buckets > HashTable.BUCKETS_MAX) {
      buckets = HashTable.BUCKETS_MAX;
    }

    Assert.GE('buckets', buckets, HashTable.BUCKETS_MIN);
    Assert.LE('buckets', buckets, HashTable.BUCKETS_MAX);
    Assert.P2('buckets', buckets);

    this.keySize = keySize;
    this.valueSize = valueSize;
    this.bucket = HashTable.bucket(keySize, valueSize);
    this.capacity = buffers * buckets * 8;
    this.length = 0;
    this.mask = buffers - 1;
    this.mode = 0; // 1 = resizing with set(), 2 = evicting with cache().

    if (
      this.capacity < elementsMin ||
      this.bucket * buckets > HashTable.BUFFER_MAX
    ) {
      throw new Error(HashTable.ERROR_MAXIMUM_CAPACITY_EXCEEDED);
    }

    this.tables = new Array<Table>(buffers);

    for (let offset = 0; offset < buffers; offset++) {
      this.tables[offset] = new Table(keySize, valueSize, this.bucket, buckets);
    }
  }

  // The size of a cache-aligned bucket, given keySize and valueSize:
  public static bucket(keySize: number, valueSize: number): number {
    Assert.GE('keySize', keySize, HashTable.KEY_MIN);
    Assert.LE('keySize', keySize, HashTable.KEY_MAX);

    if (keySize % 4) {
      throw new Error('keySize must be a multiple of 4');
    }

    Assert.GE('valueSize', valueSize, HashTable.VALUE_MIN);
    Assert.LE('valueSize', valueSize, HashTable.VALUE_MAX);

    // Bucket includes padding for 64-byte cache line alignment:
    let bucket = Math.ceil((20 + (keySize + valueSize) * 8) / 64) * 64;
    Assert.GE('bucket', bucket, 0);
    return bucket;
  }

  // The number of buckets required to support elements at 100% load factor:
  public static buckets(elements: number, buffers: number): number {
    Assert.GE('elements', elements, HashTable.ELEMENTS_MIN);
    Assert.LE('elements', elements, HashTable.ELEMENTS_MAX);  
    Assert.GE('buffers', buffers, HashTable.BUFFERS_MIN);
    Assert.LE('buffers', buffers, HashTable.BUFFERS_MAX);
    Assert.P2('buffers', buffers);
    let power = Math.ceil(Math.log2(Math.max(1, elements / 8 / buffers)));
    let buckets = Math.max(HashTable.BUCKETS_MIN, Math.pow(2, power));
    Assert.GE('buckets', buckets, HashTable.BUCKETS_MIN);
    // Buckets may exceed BUCKETS_MAX here so that buffers() can call buckets().
    Assert.P2('buckets', buckets);
    return buckets;
  }

  // The number of buffers required to support elements at 100% load factor:
  public static buffers(
    keySize: number,
    valueSize: number,
    elements: number
  ): number {
    // Objectives:
    //
    // 1. Maximize the number of buckets (>= 64) for maximum load factor.
    // 2. Minimize the number of buffers for less pointer overhead.
    //  
    // The number of buckets places an upper bound on the maximum load factor:
    // If, at maximum capacity, the number of buckets is less than 64 then the
    // maximum load factor will be less than 100% (even when evicting).
    //
    //   64 buckets enable a maximum load factor of 100%.
    //   32 buckets enable a maximum load factor of 75%.
    //   16 buckets enable a maximum load factor of 62.5%.
    //    8 buckets enable a maximum load factor of 56.25%.
    //    4 buckets enable a maximum load factor of 53.125%.
    //    2 buckets enable a maximum load factor of 51.5625%.
    //
    // Large value sizes interacting with BUFFER_MAX tend toward fewer buckets:
    //
    // When BUFFER_MAX is 2 GB, for all key and value size configurations:
    // A value size of 1 MB guarantees 128 buckets.
    // A value size of 2 MB guarantees 64 buckets.
    // A value size of 4 MB guarantees 32 buckets.
    //
    // When BUFFER_MAX is 1 GB:
    // A value size of 1 MB guarantees 64 buckets.
    // A value size of 2 MB guarantees 32 buckets.
    // A value size of 4 MB guarantees 16 buckets.
    // 
    // We therefore set VALUE_MAX to 1 MB to preclude the possibility of a cache
    // ever being artificially restricted to 75% occupancy (even when evicting).
    //
    // The above guarantees depend on KEY_MAX, VALUE_MAX and BUFFER_MAX:

    Assert.LE('HashTable.KEY_MAX', HashTable.KEY_MAX, 64);
    Assert.LE('HashTable.VALUE_MAX', HashTable.VALUE_MAX, 1048576);
    Assert.GE('HashTable.BUFFER_MAX', HashTable.BUFFER_MAX, 1073741824 - 1);
    Assert.GE('keySize', keySize, HashTable.KEY_MIN);
    Assert.LE('keySize', keySize, HashTable.KEY_MAX);

    if (keySize % 4) {
      throw new Error('keySize must be a multiple of 4');
    }

    Assert.GE('valueSize', valueSize, HashTable.VALUE_MIN);
    Assert.LE('valueSize', valueSize, HashTable.VALUE_MAX);
    Assert.GE('elements', elements, HashTable.ELEMENTS_MIN);
    Assert.LE('elements', elements, HashTable.ELEMENTS_MAX);

    let bucket = HashTable.bucket(keySize, valueSize);
    let buffers = HashTable.BUFFERS_MIN;

    Assert.GE('buffers', buffers, 1);

    let limit = 10000;

    while (limit--) {
      let buckets = HashTable.buckets(elements, buffers);
      let buffer = buckets * bucket;
      if (
        (buffers === HashTable.BUFFERS_MAX) ||
        (buckets <= HashTable.BUCKETS_MAX && buffer <= HashTable.BUFFER_MAX)
      ) {
        break;
      }
      buffers = buffers * 2;
    }

    Assert.GE('buffers', buffers, HashTable.BUFFERS_MIN);
    Assert.LE('buffers', buffers, HashTable.BUFFERS_MAX);
    Assert.P2('buffers', buffers);

    return buffers;
  }

  public static capacity(elements: number): number {
    Assert.GE('elements', elements, HashTable.ELEMENTS_MIN);
    Assert.LE('elements', elements, HashTable.ELEMENTS_MAX);

    let capacity = Math.min(Math.floor(elements * 1.3), HashTable.ELEMENTS_MAX);

    Assert.GE('capacity', capacity, elements);

    return capacity;
  }

  public cache(
    key: Buffer,
    keyOffset: number,
    value: Buffer,
    valueOffset: number
  ): number {
    if (this.mode === 1) {
      throw new Error(HashTable.ERROR_MODE);
    }

    this.mode = 2;

    if (this.valueSize === 0) {
      value = VALUE;
      valueOffset = 0;
    }

    Hash(key, keyOffset, this.keySize);

    let table = this.tables[(((H1 >> 24) << 8) | (H2 >> 24)) & this.mask];
    let result = table.cache(H1, H2, key, keyOffset, value, valueOffset);

    if (result === 0) {
      this.length++;
    }

    return result;
  }

  public exist(key: Buffer, keyOffset: number): number {
    Hash(key, keyOffset, this.keySize);
    let table = this.tables[(((H1 >> 24) << 8) | (H2 >> 24)) & this.mask];
    return table.exist(H1, H2, key, keyOffset);
  }

  public get(
    key: Buffer,
    keyOffset: number,
    value: Buffer,
    valueOffset: number
  ): number {
    if (this.valueSize === 0) {
      value = VALUE;
      valueOffset = 0;
    }
    Hash(key, keyOffset, this.keySize);
    let table = this.tables[(((H1 >> 24) << 8) | (H2 >> 24)) & this.mask];
    return table.get(H1, H2, key, keyOffset, value, valueOffset);
  }

  public set(
    key: Buffer,
    keyOffset: number,
    value: Buffer,
    valueOffset: number
  ): number {
    if (this.mode === 2) throw new Error(HashTable.ERROR_MODE);
    this.mode = 1;
    if (this.valueSize === 0) {
      value = VALUE;
      valueOffset = 0;
    }
    Hash(key, keyOffset, this.keySize);
    let h1 = H1;
    let h2 = H2;
    let table = this.tables[(((h1 >> 24) << 8) | (h2 >> 24)) & this.mask];
    let result = table.set(h1, h2, key, keyOffset, value, valueOffset);
    if (result === 1) return 1;
    if (result === 0) {
      this.length++;
      return 0;
    }
    for (let resize = 1; resize <= 2; resize++) {
      let buckets = table.buckets;
      if (table.resize(buckets << resize)) {
        this.capacity -= buckets * 8;
        this.capacity += table.buckets * 8;
        let result = table.set(h1, h2, key, keyOffset, value, valueOffset);
        if (result === 1) return 1;
        if (result === 0) {
          this.length++;
          return 0;
        }
      }
    }
    throw new Error(HashTable.ERROR_SET);
  }

  public unset(key: Buffer, keyOffset: number): number {
    Hash(key, keyOffset, this.keySize);
    let table = this.tables[(((H1 >> 24) << 8) | (H2 >> 24)) & this.mask];
    let result = table.unset(H1, H2, key, keyOffset);

    if (result === 1) {
      this.length--;
    }

    return result;
  }
}

Object.defineProperty(HashTable.prototype, 'load', {
  get: function() {
    return this.length / this.capacity;
  }
});

Object.defineProperty(HashTable.prototype, 'size', {
  get: function() {
    let size = this.capacity / 8 * this.bucket;
    Assert.GE('size', size, 0);
    return size;
  }
});

type CopyKeyValueType = (s: Buffer, sO: number, t: Buffer, tO: number) => void;

class Table {
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

// S.D.G.
