export class TokenBucket {
  constructor({ capacity, refillPerMs }) {
    this.capacity = capacity;
    this.refillPerMs = refillPerMs;
    this.buckets = new Map();
  }

  take(key, amount = 1) {
    const now = Date.now();
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = { tokens: this.capacity, updatedAt: now };
      this.buckets.set(key, bucket);
    }
    const elapsed = now - bucket.updatedAt;
    bucket.tokens = Math.min(this.capacity, bucket.tokens + elapsed * this.refillPerMs);
    bucket.updatedAt = now;
    if (bucket.tokens < amount) {
      return false;
    }
    bucket.tokens -= amount;
    return true;
  }

  sweep(maxIdleMs) {
    const now = Date.now();
    for (const [key, bucket] of this.buckets) {
      if (now - bucket.updatedAt > maxIdleMs) {
        this.buckets.delete(key);
      }
    }
  }
}

export class ConnectionCounter {
  constructor(maxPerKey) {
    this.maxPerKey = maxPerKey;
    this.counts = new Map();
  }

  tryAcquire(key) {
    const current = this.counts.get(key) || 0;
    if (current >= this.maxPerKey) {
      return false;
    }
    this.counts.set(key, current + 1);
    return true;
  }

  release(key) {
    const current = this.counts.get(key) || 0;
    if (current <= 1) {
      this.counts.delete(key);
    } else {
      this.counts.set(key, current - 1);
    }
  }
}
