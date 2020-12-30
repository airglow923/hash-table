// @ts-ignore
import * as crypto from 'crypto';
// @ts-ignore
import * as buffer from 'buffer';
import Assert from './Assert.js';
import Table from './Table.js';
import {H1, H2, Hash} from './Hash.js';

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
  public static ERROR_MAXIMUM_CAPACITY_EXCEEDED: string =
      'maximum capacity exceeded';

  // cache() and set() methods are mutually exclusive:
  // Once cache() is called, the table switches to non-resizing, caching mode.
  // Once set() is called, the table switches to resizing, second position mode.
  // This enables several optimizations and is safer:
  // 1. cache() does not need to scan second position for an element.
  // 2. cache() can assume all elements are in first position when refiltering.
  // 3. cache() might otherwise evict an element that was inserted using set().
  public static ERROR_MODE: string =
      'cache() and set() methods are mutually exclusive';

  // This might indicate an adversarial attack, or weak tabulation hash entropy:
  public static ERROR_SET: string =
      'set() failed despite multiple resize attempts';

  public keySize: number;
  public valueSize: number;
  public bucket: number;
  public capacity: number;
  public length: number;
  public mask: number;
  public mode: number;
  public tables: Array<any>;

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

    this.tables = new Array<any>(buffers);

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
  public static buffers(keySize: number, valueSize: number, elements: number) {
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

  public static capacity(elements: number) {
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
  ) {
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

// S.D.G.
