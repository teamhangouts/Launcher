export class TaggedError extends Error {
  constructor(code, message, extra = {}) {
    super(`${code}: ${message}`);
    this.code = code;
    this.extra = extra;
  }
}

export const Codes = {
  IdentifierTaken: "A1",
  InvalidCredentials: "A2",
  Locked: "A3",
  ChallengeExpired: "A4",
  ChallengeInvalid: "A5",
  RateLimited: "A6",
  MalformedRequest: "A7",
  InternalError: "A8"
};

export function taggedError(code, message, extra) {
  return new TaggedError(code, message, extra);
}
