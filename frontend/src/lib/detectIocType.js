const IPV4_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}$/;
// Standart tam/kısaltılmış IPv6 biçimlerinin (::1, fe80::1, 2001:db8::ff00:42:8329 vb.) hepsini kapsar.
const IPV6_REGEX =
  /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/;
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
  if (IPV6_REGEX.test(value)) {
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
