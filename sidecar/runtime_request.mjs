export const ALLOWED_CORS_ORIGINS = new Set([
  "http://127.0.0.1:8080",
  "http://localhost:8080"
]);

export const ERR_UNAUTHORIZED_ORIGIN = "ERR_UNAUTHORIZED_ORIGIN";

export function isAllowedCorsOrigin(origin) {
  return origin === undefined || origin === null || origin === "" || ALLOWED_CORS_ORIGINS.has(origin);
}

export function corsHeadersForOrigin(origin) {
  if (!origin || !ALLOWED_CORS_ORIGINS.has(origin)) return {};
  return {
    "access-control-allow-origin": origin,
    "vary": "Origin"
  };
}

export function createRuntimeInput(request, policy) {
  const sanitizedRequest = { ...request };
  delete sanitizedRequest.policy_document;
  return {
    ...sanitizedRequest,
    policy_document: policy
  };
}
