import { describe, expect, it } from "vitest";
import { detectIocType } from "./detectIocType";

describe("detectIocType", () => {
  it("boş veya sadece boşluk içeren girdide null döner", () => {
    expect(detectIocType("")).toBeNull();
    expect(detectIocType("   ")).toBeNull();
  });

  it("geçerli IPv4 adreslerini tanır", () => {
    expect(detectIocType("8.8.8.8")).toBe("ip");
    expect(detectIocType("192.168.1.1")).toBe("ip");
    expect(detectIocType("255.255.255.255")).toBe("ip");
  });

  it("oktet 255'i aşan IPv4 benzeri değeri IP olarak tanımaz", () => {
    expect(detectIocType("999.999.999.999")).not.toBe("ip");
  });

  it("geçerli IPv6 adreslerini tanır", () => {
    expect(detectIocType("::1")).toBe("ip");
    expect(detectIocType("fe80::1")).toBe("ip");
    expect(detectIocType("2001:db8::ff00:42:8329")).toBe("ip");
  });

  it("MD5/SHA1/SHA256 hash uzunluklarını tanır", () => {
    expect(detectIocType("a".repeat(32))).toBe("hash"); // MD5
    expect(detectIocType("b".repeat(40))).toBe("hash"); // SHA1
    expect(detectIocType("c".repeat(64))).toBe("hash"); // SHA256
  });

  it("http/https ile başlayan değerleri URL olarak tanır", () => {
    expect(detectIocType("http://example.com")).toBe("url");
    expect(detectIocType("https://example.com/path?q=1")).toBe("url");
  });

  it("geçerli domain adlarını tanır", () => {
    expect(detectIocType("example.com")).toBe("domain");
    expect(detectIocType("sub.example.co.uk")).toBe("domain");
  });

  it("hiçbir formata uymayan değerde null döner", () => {
    expect(detectIocType("!!!not valid!!!")).toBeNull();
    expect(detectIocType("tek-kelime")).toBeNull();
  });

  it("baştaki/sondaki boşlukları temizleyip değerlendirir", () => {
    expect(detectIocType("  8.8.8.8  ")).toBe("ip");
  });
});
