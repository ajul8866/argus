/** Serializes work for each key while allowing different keys to run independently. */
export class KeyedSerialQueue {
  private readonly tails = new Map<string, Promise<void>>();

  get size(): number {
    return this.tails.size;
  }

  run<T>(key: string, operation: () => Promise<T> | T): Promise<T> {
    const previous = this.tails.get(key) ?? Promise.resolve();
    const result = previous.then(operation, operation);
    const release = () => {
      if (this.tails.get(key) === tail) this.tails.delete(key);
    };
    const tail = result.then(release, release);
    this.tails.set(key, tail);
    return result;
  }
}
