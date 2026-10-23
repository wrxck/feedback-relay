export interface RateDecision {
  allowed: boolean;
  retryAfterMs: number;
}

export interface RateLimiter {
  hit(key: string, now: number): Promise<RateDecision>;
}

export interface MemoryRateLimitOptions {
  max: number;
  windowMs: number;
  maxKeys?: number;
}

// a fixed window per key: simple, cheap and good enough for a feedback form
export function createMemoryRateLimiter(options: MemoryRateLimitOptions): RateLimiter {
  const maxKeys = options.maxKeys ?? 50_000;
  const windows = new Map<string, { start: number; count: number }>();
  return {
    hit(key, now) {
      let window = windows.get(key);
      if (!window || now - window.start >= options.windowMs) {
        windows.delete(key);
        if (windows.size >= maxKeys) {
          const oldest = windows.keys().next().value;
          if (oldest !== undefined) windows.delete(oldest);
        }
        window = { start: now, count: 0 };
        windows.set(key, window);
      }
      window.count += 1;
      const allowed = window.count <= options.max;
      const retryAfterMs = allowed ? 0 : window.start + options.windowMs - now;
      return Promise.resolve({ allowed, retryAfterMs });
    },
  };
}
