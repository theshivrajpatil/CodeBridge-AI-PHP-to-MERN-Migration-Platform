export class HttpError extends Error {
  constructor(status, message, errors) {
    super(message);
    this.status = status;
    this.errors = errors;
  }
}
export const notImplemented = (message) => new HttpError(501, message || 'Not implemented');
