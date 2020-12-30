export default class Assert {
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
  }

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
  }

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
  }
}
