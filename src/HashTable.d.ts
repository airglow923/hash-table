// Type definitions for @ronomon/hash-table 2.0
// Project: https://github.com/ronomon/hash-table#readme
// Definitions by: airglow923 <https://github.com/me>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped

export = ronomon__hash_table;

declare class ronomon__hash_table {
    constructor(keySize: any, valueSize: any, elementsMin: any, elementsMax: any);

    cache(key: any, keyOffset: any, value: any, valueOffset: any): any;

    exist(key: any, keyOffset: any): any;

    get(key: any, keyOffset: any, value: any, valueOffset: any): any;

    set(key: any, keyOffset: any, value: any, valueOffset: any): any;

    unset(key: any, keyOffset: any): any;

    static BUCKETS_MAX: number;

    static BUCKETS_MIN: number;

    static BUFFERS_MAX: number;

    static BUFFERS_MIN: number;

    static BUFFER_MAX: number;

    static ELEMENTS_MAX: number;

    static ELEMENTS_MIN: number;

    static ERROR_MAXIMUM_CAPACITY_EXCEEDED: string;

    static ERROR_MODE: string;

    static ERROR_SET: string;

    static KEY_MAX: number;

    static KEY_MIN: number;

    static VALUE_MAX: number;

    static VALUE_MIN: number;

    static bucket(keySize: any, valueSize: any): any;

    static buckets(elements: any, buffers: any): any;

    static buffers(keySize: any, valueSize: any, elements: any): any;

    static capacity(elements: any): any;

}

