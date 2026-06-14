/**
 * Injectable time source. Production uses {@link systemClock}; tests pass a fake
 * clock to make TTL/expiry behavior deterministic without real timers.
 */
export interface Clock {
  /** Current time in milliseconds since the Unix epoch. */
  now(): number;
}

/** Default clock backed by `Date.now()`. */
export const systemClock: Clock = {
  now: () => Date.now(),
};
