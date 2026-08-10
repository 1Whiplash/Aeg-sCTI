const IPV4_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const HASH_REGEX = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
const DOMAIN_REGEX = /^(?!-)[a-zA-Z0-9-]{1,63}(?:\.[a-zA-Z0-9-]{1,63})+$/;

/** Girilen metnin IP / URL / hash / domain olma ihtimalini tahmin eder. */
export function detectIocType(rawValue) {
  const value = rawValue.trim();
  if (!value) return null;

  if (value.startsWith("http://") || value.startsWith("https://")) {
    return "url";
  }
  if (IPV4_REGEX.test(value) && value.split(".").every((octet) => Number(octet) <= 255)) {
    return "ip";
  }
  if (HASH_REGEX.test(value)) {
    return "hash";
  }
  if (DOMAIN_REGEX.test(value)) {
    return "domain";
  }
  return null;
}
