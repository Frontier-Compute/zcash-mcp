const DELTA_SECONDS = /^[0-9]+$/;
const IMF_FIXDATE = /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), (?:0[1-9]|[12][0-9]|3[01]) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{4} (?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] GMT$/;

function parseDeltaSeconds(value) {
  if (typeof value !== "string" || !DELTA_SECONDS.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

export function registryFreshnessFromHeaders(headers, observedAtSeconds) {
  const observed = Number.isSafeInteger(observedAtSeconds) && observedAtSeconds >= 0
    ? observedAtSeconds
    : null;
  if (!headers || typeof headers.get !== "function") {
    return { ageSeconds: null, maxAgeSeconds: null, observedAtSeconds: observed, responseDateSeconds: null };
  }

  const ageSeconds = parseDeltaSeconds(headers.get("age"));
  let maximumCount = 0;
  let maxAgeSeconds = null;
  for (const rawDirective of String(headers.get("cache-control") ?? "").split(",")) {
    const directive = rawDirective.trim();
    const equals = directive.indexOf("=");
    const name = (equals === -1 ? directive : directive.slice(0, equals)).trim().toLowerCase();
    if (name !== "max-age") continue;
    maximumCount += 1;
    const value = equals === -1 ? null : directive.slice(equals + 1).trim();
    maxAgeSeconds = parseDeltaSeconds(value);
  }
  if (maximumCount !== 1) maxAgeSeconds = null;

  const dateValue = headers.get("date");
  const parsedDateMilliseconds = typeof dateValue === "string" && IMF_FIXDATE.test(dateValue)
    ? Date.parse(dateValue)
    : null;
  const canonicalDate = Number.isFinite(parsedDateMilliseconds) ? new Date(parsedDateMilliseconds).toUTCString() : null;
  const parsedDate = canonicalDate === dateValue ? parsedDateMilliseconds / 1000 : null;
  const responseDateSeconds = Number.isSafeInteger(parsedDate) && parsedDate >= 0 ? parsedDate : null;
  return { ageSeconds, maxAgeSeconds, observedAtSeconds: observed, responseDateSeconds };
}
