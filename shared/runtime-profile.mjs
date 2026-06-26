// Canonical MNDE_PROFILE parser. All callers must use this — never compare the
// raw env string directly so that case variations and typos fail explicitly
// rather than silently degrading to local/dev mode.
//
// Valid values (case-insensitive): "production", "local".
// Unset / empty string => "local" (backward-compatible default).
// Unknown value => ok:false so the caller can fail closed at startup.

const VALID_PROFILES = new Set(["production", "local"]);

export function parseRuntimeProfile(raw) {
  if (raw === undefined || raw === null || String(raw).trim() === "") {
    return { ok: true, profile: "local" };
  }
  const normalized = String(raw).toLowerCase().trim();
  if (!VALID_PROFILES.has(normalized)) {
    return {
      ok: false,
      profile: "local",
      reason_code: "ERR_UNKNOWN_PROFILE",
      detail: `MNDE_PROFILE value '${raw}' is not recognized. Valid values: 'production', 'local' (case-insensitive). Unset or set to 'local' for development.`
    };
  }
  return { ok: true, profile: normalized };
}
