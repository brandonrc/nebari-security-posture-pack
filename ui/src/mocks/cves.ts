import type { Severity } from '@/api/types';

/** Realistic CVE pool for fixtures: [id, package, pkgType, severity, installed, fixed|null, cvss, title]. */
export type CveSeed = [string, string, string, Severity, string, string | null, number | null, string];

export const OS_CVES: CveSeed[] = [
  ['CVE-2024-6119', 'libssl3', 'apk', 'high', '3.3.1-r3', '3.3.2-r0', 7.5, 'openssl: Possible denial of service in X.509 name checks'],
  ['CVE-2024-5535', 'libssl3', 'apk', 'low', '3.3.1-r3', '3.3.1-r4', 3.7, 'openssl: SSL_select_next_proto buffer overread'],
  ['CVE-2024-2511', 'openssl', 'deb', 'medium', '3.0.11-1~deb12u2', '3.0.13-1~deb12u1', 5.9, 'openssl: Unbounded memory growth with session handling in TLSv1.3'],
  ['CVE-2023-45853', 'zlib1g', 'deb', 'critical', '1:1.2.13.dfsg-1', null, 9.8, 'zlib: integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_6'],
  ['CVE-2024-37371', 'libkrb5-3', 'deb', 'critical', '1.20.1-2+deb12u1', '1.20.1-2+deb12u2', 9.1, 'krb5: GSS message token handling'],
  ['CVE-2024-26461', 'libkrb5-3', 'deb', 'medium', '1.20.1-2+deb12u1', null, 5.5, 'krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c'],
  ['CVE-2023-4911', 'libc6', 'deb', 'high', '2.36-9+deb12u1', '2.36-9+deb12u3', 7.8, 'glibc: buffer overflow in ld.so leading to privilege escalation (Looney Tunables)'],
  ['CVE-2024-2961', 'libc6', 'deb', 'high', '2.36-9+deb12u3', '2.36-9+deb12u7', 8.8, 'glibc: Out of bounds write in iconv may lead to remote code execution'],
  ['CVE-2024-33599', 'libc6', 'deb', 'high', '2.36-9+deb12u3', '2.36-9+deb12u7', 7.6, 'glibc: stack-based buffer overflow in netgroup cache'],
  ['CVE-2023-52425', 'libexpat1', 'deb', 'high', '2.5.0-1', '2.5.0-1+deb12u1', 7.5, 'expat: parsing large tokens can trigger a denial of service'],
  ['CVE-2024-45490', 'libexpat1', 'deb', 'critical', '2.5.0-1', '2.5.0-1+deb12u1', 9.8, 'libexpat: Negative Length Parsing Vulnerability in libexpat'],
  ['CVE-2024-45491', 'libexpat1', 'deb', 'critical', '2.5.0-1', '2.5.0-1+deb12u1', 9.8, 'libexpat: Integer Overflow or Wraparound'],
  ['CVE-2024-8176', 'libexpat1', 'deb', 'high', '2.5.0-1', null, 7.5, 'libexpat: expat: Improper Restriction of XML Entity Expansion Depth'],
  ['CVE-2024-2398', 'curl', 'apk', 'medium', '8.5.0-r0', '8.7.1-r0', 6.5, 'curl: HTTP/2 push headers memory-leak'],
  ['CVE-2024-7264', 'libcurl', 'apk', 'medium', '8.5.0-r0', '8.9.1-r0', 6.5, 'curl: ASN.1 date parser overread'],
  ['CVE-2024-6874', 'libcurl', 'apk', 'low', '8.5.0-r0', '8.9.0-r0', 4.3, 'curl: macidn punycode buffer overread'],
  ['CVE-2023-50495', 'libncursesw6', 'deb', 'medium', '6.4-4', null, 6.5, 'ncurses: segmentation fault via _nc_wrap_entry()'],
  ['CVE-2024-28182', 'libnghttp2-14', 'deb', 'medium', '1.52.0-1+deb12u1', '1.52.0-1+deb12u2', 5.3, 'nghttp2: CONTINUATION frames DoS'],
  ['CVE-2024-56171', 'libxml2', 'apk', 'high', '2.12.6-r0', '2.12.10-r0', 7.8, 'libxml2: Use-After-Free in libxml2'],
  ['CVE-2025-24928', 'libxml2', 'apk', 'high', '2.12.6-r0', '2.12.10-r0', 7.8, 'libxml2: Stack-based buffer overflow in xmlSnprintfElements'],
  ['CVE-2024-22365', 'libpam0g', 'deb', 'medium', '1.5.2-6+deb12u1', null, 5.5, 'pam: allowing unprivileged user to block another user namespace'],
  ['CVE-2023-29383', 'login', 'deb', 'low', '1:4.13+dfsg1-1', null, 3.3, 'shadow-utils: possible password leak during passwd(1) change'],
  ['CVE-2022-0563', 'util-linux', 'deb', 'low', '2.38.1-5+b1', null, 5.5, 'util-linux: partial disclosure of arbitrary files in chfn and chsh'],
  ['CVE-2011-3374', 'apt', 'deb', 'negligible', '2.6.1', null, 3.7, 'It was found that apt-key in apt, all versions, do not correctly validate gpg keys'],
  ['CVE-2017-18018', 'coreutils', 'deb', 'negligible', '9.1-1', null, 4.7, 'coreutils: race condition vulnerability in chown and chgrp'],
  ['CVE-2024-38428', 'wget', 'deb', 'critical', '1.21.3-1+b2', '1.21.3-1+deb12u1', 9.1, 'wget: Misinterpretation of input may lead to improper behavior'],
  ['CVE-2023-2650', 'libcrypto3', 'apk', 'medium', '3.1.0-r4', '3.1.1-r0', 6.5, 'openssl: Possible DoS translating ASN.1 object identifiers'],
  ['CVE-2024-0727', 'libcrypto3', 'apk', 'medium', '3.1.4-r2', '3.1.4-r5', 5.5, 'openssl: denial of service via null dereference'],
  ['CVE-2023-7008', 'libsystemd0', 'deb', 'medium', '252.17-1~deb12u1', null, 5.9, 'systemd-resolved: Unsigned name response in signed zone is not refused'],
  ['CVE-2024-12797', 'libssl3', 'apk', 'high', '3.3.2-r0', '3.3.3-r0', 7.4, 'openssl: RFC7250 handshakes with unauthenticated servers don\'t abort as expected'],
];

export const GO_CVES: CveSeed[] = [
  ['CVE-2024-45337', 'golang.org/x/crypto', 'gobinary', 'critical', 'v0.27.0', '0.31.0', 9.1, 'golang.org/x/crypto/ssh: Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass'],
  ['CVE-2024-45338', 'golang.org/x/net', 'gobinary', 'medium', 'v0.30.0', '0.33.0', 5.3, 'golang.org/x/net/html: Non-linear parsing of case-insensitive content'],
  ['CVE-2023-44487', 'golang.org/x/net', 'gobinary', 'high', 'v0.15.0', '0.17.0', 7.5, 'HTTP/2: Multiple HTTP/2 enabled web servers are vulnerable to a DDoS attack (Rapid Reset Attack)'],
  ['CVE-2023-39325', 'golang.org/x/net', 'gobinary', 'high', 'v0.15.0', '0.17.0', 7.5, 'golang: net/http, x/net/http2: rapid stream resets can cause excessive work'],
  ['CVE-2024-24790', 'stdlib', 'gobinary', 'critical', 'v1.21.9', '1.21.11, 1.22.4', 9.8, 'golang: net/netip: Unexpected behavior from Is methods for IPv4-mapped IPv6 addresses'],
  ['CVE-2024-34156', 'stdlib', 'gobinary', 'high', 'v1.22.5', '1.22.7, 1.23.1', 7.5, 'encoding/gob: golang: Calling Decoder.Decode on a message which contains deeply nested structures can cause a panic'],
  ['CVE-2024-34158', 'stdlib', 'gobinary', 'high', 'v1.22.5', '1.22.7, 1.23.1', 7.5, 'go/build/constraint: golang: Calling Parse on a "// +build" build tag line with deeply nested expressions can cause a panic'],
  ['CVE-2025-22869', 'golang.org/x/crypto', 'gobinary', 'high', 'v0.31.0', '0.35.0', 7.5, 'golang.org/x/crypto/ssh: Denial of Service in the Key Exchange'],
  ['CVE-2024-24786', 'google.golang.org/protobuf', 'gobinary', 'medium', 'v1.31.0', '1.33.0', 5.9, 'golang-protobuf: encoding/protojson, internal/encoding/json: infinite loop in protojson.Unmarshal'],
  ['CVE-2024-21626', 'github.com/opencontainers/runc', 'gobinary', 'high', 'v1.1.9', '1.1.12', 8.6, 'runc: file descriptor leak'],
  ['CVE-2025-21613', 'github.com/go-git/go-git/v5', 'gobinary', 'critical', 'v5.11.0', '5.13.0', 9.8, 'go-git: argument injection via the URL field'],
  ['CVE-2024-41110', 'github.com/docker/docker', 'gobinary', 'critical', 'v24.0.7+incompatible', '25.0.6, 26.1.5, 27.1.1', 9.9, 'moby: Authz zero length regression'],
  ['CVE-2025-27144', 'github.com/go-jose/go-jose/v4', 'gobinary', 'medium', 'v4.0.2', '4.0.5', 5.3, 'go-jose: Go JOSE\'s Parsing Vulnerable to Denial of Service'],
  ['CVE-2024-6104', 'github.com/hashicorp/go-retryablehttp', 'gobinary', 'medium', 'v0.7.4', '0.7.7', 6.0, 'go-retryablehttp: url might write sensitive information to log file'],
];

export const PY_CVES: CveSeed[] = [
  ['CVE-2024-6345', 'setuptools', 'python-pkg', 'high', '65.5.1', '70.0.0', 8.8, 'pypa/setuptools: Remote code execution via download functions in the package_index module'],
  ['CVE-2022-40897', 'setuptools', 'python-pkg', 'medium', '65.5.1', '65.5.1', 5.9, 'pypa-setuptools: Regular Expression Denial of Service (ReDoS) in package_index.py'],
  ['CVE-2024-3651', 'idna', 'python-pkg', 'medium', '3.6', '3.7', 6.2, 'python-idna: potential DoS via resource consumption via specially crafted inputs to idna.encode()'],
  ['CVE-2024-35195', 'requests', 'python-pkg', 'medium', '2.31.0', '2.32.0', 5.6, 'requests: subsequent requests to the same host ignore cert verification'],
  ['CVE-2024-39689', 'certifi', 'python-pkg', 'low', '2024.2.2', '2024.7.4', 7.5, 'python-certifi: Remove GLOBALTRUST root certificate'],
  ['CVE-2024-37891', 'urllib3', 'python-pkg', 'medium', '2.0.7', '2.2.2', 4.4, 'urllib3: proxy-authorization request header is not stripped during cross-origin redirects'],
  ['CVE-2024-1135', 'gunicorn', 'python-pkg', 'high', '21.2.0', '22.0.0', 7.5, 'python-gunicorn: HTTP Request Smuggling due to improper validation of Transfer-Encoding headers'],
  ['CVE-2024-34064', 'jinja2', 'python-pkg', 'medium', '3.1.3', '3.1.4', 5.4, 'jinja2: accepts keys containing non-attribute characters'],
  ['CVE-2023-6129', 'cryptography', 'python-pkg', 'medium', '41.0.7', '42.0.0', 6.5, 'openssl: POLY1305 MAC implementation corrupts vector registers on PowerPC'],
  ['CVE-2024-26130', 'cryptography', 'python-pkg', 'high', '41.0.7', '42.0.4', 7.5, 'cryptography: NULL pointer dereference with pkcs12.serialize_key_and_certificates'],
];

export const NODE_CVES: CveSeed[] = [
  ['CVE-2024-52798', 'path-to-regexp', 'node-pkg', 'high', '0.1.10', '0.1.12', 7.5, 'path-to-regexp: Unpatched `path-to-regexp` ReDoS in 0.1.x'],
  ['CVE-2024-21538', 'cross-spawn', 'node-pkg', 'high', '7.0.3', '7.0.5', 7.5, 'cross-spawn: regular expression denial of service'],
  ['CVE-2024-4067', 'micromatch', 'node-pkg', 'medium', '4.0.5', '4.0.8', 5.3, 'micromatch: vulnerable to Regular Expression Denial of Service'],
  ['CVE-2024-45296', 'path-to-regexp', 'node-pkg', 'high', '0.1.7', '0.1.10', 7.5, 'path-to-regexp: Backtracking regular expressions cause ReDoS'],
  ['CVE-2024-43796', 'express', 'node-pkg', 'low', '4.19.2', '4.20.0', 5.0, 'express: Improper Input Handling in Express Redirects'],
  ['CVE-2024-29041', 'express', 'node-pkg', 'medium', '4.18.2', '4.19.2', 6.1, 'express: cause malformed URLs to be evaluated'],
];

export const JAVA_CVES: CveSeed[] = [
  ['CVE-2024-47561', 'org.apache.avro:avro', 'jar', 'critical', '1.11.3', '1.11.4', 9.3, 'apache-avro: Schema parsing may trigger Remote Code Execution (RCE)'],
  ['CVE-2024-7254', 'com.google.protobuf:protobuf-java', 'jar', 'high', '3.25.3', '3.25.5', 7.5, 'protobuf: StackOverflow vulnerability in Protocol Buffers'],
  ['CVE-2023-6378', 'ch.qos.logback:logback-classic', 'jar', 'high', '1.4.11', '1.4.12', 7.1, 'logback: serialization vulnerability in logback receiver'],
  ['CVE-2024-38809', 'org.springframework:spring-web', 'jar', 'medium', '6.1.10', '6.1.12', 5.3, 'spring-web: ETag header DoS'],
  ['CVE-2024-1023', 'io.vertx:vertx-core', 'jar', 'medium', '4.5.1', '4.5.2', 6.5, 'vert.x: io.vertx/vertx-core: memory leak due to the use of Netty FastThreadLocal data structures'],
  ['CVE-2024-29025', 'io.netty:netty-codec-http', 'jar', 'medium', '4.1.100.Final', '4.1.108.Final', 5.3, 'netty-codec-http: Allocation of Resources Without Limits or Throttling'],
];
