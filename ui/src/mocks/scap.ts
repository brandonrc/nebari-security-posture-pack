/**
 * §14 SCAP mock data: three benchmarks (RHEL 9 DISA, Ubuntu 22.04 SSG, PostgreSQL 15 DISA) with
 * 30 rules each, evaluated against eight of the fixture images (one with two benchmarks, one
 * with degraded rootfs fidelity); every other image has no applicable benchmark (`stig: null`).
 * Deterministic (own seeded PRNG, so the rest of the fixtures are unchanged).
 */
import type {
  ImageStig,
  ImageStigBenchmark,
  ImageStigBrief,
  ScannerHealth,
  ScapCat,
  ScapContentVersion,
  ScapResult,
  ScapRule,
  ScapSettings,
  StigBenchmark,
  StigBenchmarkRule,
  StigRollup,
} from '@/api/types';
import { images, NOW } from './fixtures';

function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = mulberry32(20261005);
const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(NOW - msAgo).toISOString();

/** `run` = needs a running system (OpenSCAP in chroot mode reports notchecked); `na` = not applicable in a container; `hot` = commonly failing. */
type Kind = 'run' | 'na' | 'hot' | undefined;
type RuleSeed = [slug: string, title: string, cat: ScapCat, cci: string, fix: string, kind?: Kind];

const OS_RULES: RuleSeed[] = [
  ['installed_OS_is_vendor_supported', 'The operating system must be a vendor-supported release.', 'cat1', 'CCI-000366', 'Upgrade to a supported version of the operating system.'],
  ['package_telnet-server_removed', 'The operating system must not have the telnet-server package installed.', 'cat1', 'CCI-000381', 'Remove the telnet-server package.'],
  ['no_empty_passwords', 'The operating system must not allow accounts configured with blank or null passwords.', 'cat1', 'CCI-000366', 'Remove any instances of the "nullok" option from the PAM system-auth and password-auth files.', 'hot'],
  ['accounts_no_uid_except_zero', 'The operating system must ensure root is the only account with an unrestricted UID of 0.', 'cat1', 'CCI-000366', 'Change the UID of any account other than root that has a UID of 0.'],
  ['package_aide_installed', 'The operating system must have the AIDE package installed.', 'cat2', 'CCI-002696', 'Install AIDE, initialise the database and schedule periodic checks.', 'hot'],
  ['enable_fips_mode', 'The operating system must implement NIST FIPS-validated cryptography.', 'cat1', 'CCI-000068', 'Enable FIPS mode on the host kernel (fips-mode-setup --enable).', 'run'],
  ['configure_crypto_policy', 'The operating system must implement DoD-approved encryption in the system-wide crypto policy.', 'cat2', 'CCI-002450', 'Set the system-wide crypto policy to FIPS (update-crypto-policies --set FIPS).', 'hot'],
  ['file_permissions_binary_dirs', 'System commands must have mode 0755 or less permissive.', 'cat2', 'CCI-001499', 'chmod 0755 any system command in /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin and /usr/local/sbin that is more permissive.'],
  ['file_ownership_binary_dirs', 'System commands must be owned by root.', 'cat2', 'CCI-001499', 'chown root any system command not owned by root.'],
  ['file_permissions_library_dirs', 'System-wide shared library files must have mode 0755 or less permissive.', 'cat2', 'CCI-001499', 'chmod 0755 any library file in /lib, /lib64, /usr/lib and /usr/lib64 that is more permissive.'],
  ['file_permissions_etc_shadow', 'The /etc/shadow file must have mode 0000 to prevent unauthorized access.', 'cat2', 'CCI-002165', 'chmod 0000 /etc/shadow', 'hot'],
  ['file_owner_etc_passwd', 'The /etc/passwd file must be owned by root.', 'cat2', 'CCI-002165', 'chown root /etc/passwd'],
  ['accounts_password_pam_minlen', 'The operating system must enforce a minimum 15-character password length.', 'cat2', 'CCI-004066', 'Set "minlen = 15" in /etc/security/pwquality.conf.', 'hot'],
  ['set_password_hashing_algorithm_logindefs', 'The operating system must store only encrypted representations of passwords using SHA-512.', 'cat2', 'CCI-004062', 'Set "ENCRYPT_METHOD SHA512" in /etc/login.defs.'],
  ['accounts_passwords_pam_faillock_deny', 'The operating system must automatically lock an account after three unsuccessful logon attempts.', 'cat2', 'CCI-000044', 'Set "deny = 3" in /etc/security/faillock.conf.', 'hot'],
  ['sudo_require_reauthentication', 'The operating system must require re-authentication when using the sudo command.', 'cat2', 'CCI-002038', 'Set "Defaults timestamp_timeout=0" in /etc/sudoers.', 'na'],
  ['package_rsh-server_removed', 'The operating system must not have the rsh-server package installed.', 'cat1', 'CCI-000381', 'Remove the rsh-server package.'],
  ['package_audit_installed', 'The operating system audit package must be installed.', 'cat2', 'CCI-000130', 'Install the audit package.', 'hot'],
  ['service_auditd_enabled', 'The audit service must be enabled and running.', 'cat2', 'CCI-000169', 'systemctl enable --now auditd', 'run'],
  ['audit_rules_dac_modification_chmod', 'The operating system must audit all uses of the chmod, fchmod and fchmodat system calls.', 'cat2', 'CCI-000172', 'Add "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod" to the audit rules.', 'run'],
  ['sysctl_kernel_randomize_va_space', 'The operating system must implement address space layout randomization.', 'cat2', 'CCI-002824', 'Set kernel.randomize_va_space = 2.', 'run'],
  ['sysctl_kernel_kexec_load_disabled', 'The operating system must prevent the loading of a new kernel for later execution.', 'cat2', 'CCI-003992', 'Set kernel.kexec_load_disabled = 1.', 'run'],
  ['sshd_disable_empty_passwords', 'The SSH daemon must not allow authentication using an empty password.', 'cat1', 'CCI-000766', 'Set "PermitEmptyPasswords no" in /etc/ssh/sshd_config.', 'na'],
  ['sshd_disable_root_login', 'The SSH daemon must not permit direct logons to the root account.', 'cat2', 'CCI-004045', 'Set "PermitRootLogin no" in /etc/ssh/sshd_config.', 'na'],
  ['banner_etc_issue', 'The operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local access.', 'cat2', 'CCI-000048', 'Write the DoD banner text to /etc/issue.', 'hot'],
  ['ensure_gpgcheck_globally_activated', 'The operating system must check the signature of packages from repositories before installation.', 'cat1', 'CCI-001749', 'Enable signature checking for every configured package repository.'],
  ['clean_components_post_updating', 'The operating system must remove all software components after updated versions have been installed.', 'cat3', 'CCI-002617', 'Set "clean_requirements_on_remove=True" (dnf) or run "apt-get autoremove".'],
  ['accounts_umask_etc_login_defs', 'The operating system must define default permissions for all authenticated users so the user can only read and modify their own files.', 'cat2', 'CCI-000366', 'Set "UMASK 077" in /etc/login.defs.', 'hot'],
  ['accounts_max_concurrent_login_sessions', 'The operating system must limit the number of concurrent sessions to ten for all accounts and/or account types.', 'cat3', 'CCI-000054', 'Add "* hard maxlogins 10" to /etc/security/limits.conf.'],
  ['disable_users_coredumps', 'The operating system must disable core dumps for all users.', 'cat2', 'CCI-000366', 'Add "* hard core 0" to /etc/security/limits.conf.'],
];

const PG_RULES: RuleSeed[] = [
  ['pg_enforce_authorizations', 'PostgreSQL must enforce approved authorizations for logical access to information and system resources.', 'cat1', 'CCI-000213', 'Revoke privileges not required for each role; grant via roles only.'],
  ['pg_fips_crypto', 'PostgreSQL must use NIST FIPS 140-2/140-3 validated cryptographic modules for cryptographic operations.', 'cat1', 'CCI-000068', 'Build/run PostgreSQL against a FIPS-validated OpenSSL on a FIPS-enabled host.', 'run'],
  ['pg_data_at_rest', 'PostgreSQL must protect the confidentiality and integrity of all information at rest.', 'cat1', 'CCI-001199', 'Encrypt the data directory volume or use pgcrypto for sensitive columns.', 'run'],
  ['pg_hba_no_trust', 'PostgreSQL must not use trust authentication for any connection in pg_hba.conf.', 'cat1', 'CCI-000764', 'Replace every "trust" method in pg_hba.conf with "scram-sha-256" and reload.', 'hot'],
  ['pg_password_encryption', 'PostgreSQL must store passwords using scram-sha-256 (password_encryption).', 'cat2', 'CCI-000196', 'Set password_encryption = scram-sha-256 and reset existing passwords.'],
  ['pg_audit_privilege_changes', 'PostgreSQL must generate audit records when privileges/permissions are added.', 'cat2', 'CCI-000172', 'Load pgaudit (shared_preload_libraries) and set pgaudit.log = "role".', 'hot'],
  ['pg_audit_content', 'PostgreSQL must produce audit records containing sufficient information to establish what type of events occurred.', 'cat2', 'CCI-000130', 'Set log_line_prefix to include %m %u %d %r %p %c and enable pgaudit.', 'hot'],
  ['pg_audit_on_startup', 'PostgreSQL must initiate session auditing upon startup.', 'cat2', 'CCI-001464', 'Add pgaudit to shared_preload_libraries and set pgaudit.log in postgresql.conf.', 'hot'],
  ['pg_log_connections', 'PostgreSQL must log connections and disconnections.', 'cat2', 'CCI-000172', 'Set log_connections = on and log_disconnections = on.'],
  ['pg_log_line_prefix_time', 'PostgreSQL must include a time stamp in every log line.', 'cat2', 'CCI-000131', 'Include %m in log_line_prefix.'],
  ['pg_audit_log_read', 'The audit information produced by PostgreSQL must be protected from unauthorized read access.', 'cat2', 'CCI-000162', 'Set log_file_mode = 0600 and restrict the log directory to the postgres user.'],
  ['pg_audit_config_protect', 'PostgreSQL must protect its audit configuration from unauthorized modification.', 'cat2', 'CCI-000171', 'chown postgres and chmod 0600 postgresql.conf and pg_hba.conf.'],
  ['pg_data_dir_perms', 'PostgreSQL must limit privileges to change software modules and the data directory (mode 0700).', 'cat2', 'CCI-001499', 'chmod 0700 $PGDATA', 'hot'],
  ['pg_port', 'PostgreSQL must be configured to prohibit or restrict the use of unauthorized network ports.', 'cat2', 'CCI-000382', 'Listen only on the documented port and interfaces (port, listen_addresses).'],
  ['pg_ssl_on', 'PostgreSQL must use TLS to protect the confidentiality of transmitted information.', 'cat2', 'CCI-002418', 'Set ssl = on with a DoD-approved certificate and key.', 'hot'],
  ['pg_ssl_integrity', 'PostgreSQL must implement cryptographic mechanisms to prevent unauthorized modification of information during transmission.', 'cat2', 'CCI-002421', 'Require hostssl entries in pg_hba.conf for all remote connections.', 'hot'],
  ['pg_session_invalidate', 'PostgreSQL must invalidate session identifiers upon user logout or other session termination.', 'cat2', 'CCI-001185', 'Use the default backend-per-session model; do not pool sessions across users.'],
  ['pg_separate_admin', 'PostgreSQL must separate user functionality from database management functionality.', 'cat2', 'CCI-001082', 'Do not grant SUPERUSER, CREATEROLE or CREATEDB to application roles.'],
  ['pg_isolate_security', 'PostgreSQL must isolate security functions from non-security functions.', 'cat2', 'CCI-001084', 'Keep security objects in a dedicated schema owned by an administrative role.'],
  ['pg_error_detail', 'PostgreSQL must reveal detailed error messages only to the ISSO, ISSM, SA and DBA.', 'cat2', 'CCI-001314', 'Set client_min_messages = error.'],
  ['pg_error_nonpriv', 'PostgreSQL must provide non-privileged users with error messages that do not reveal exploitable information.', 'cat2', 'CCI-001312', 'Set log_error_verbosity = default and client_min_messages = error.'],
  ['pg_config_change_restrict', 'PostgreSQL must enforce access restrictions associated with changes to its configuration.', 'cat2', 'CCI-001813', 'Restrict ALTER SYSTEM and the configuration files to the database administrator role.'],
  ['pg_unused_extensions', 'Unused database components, DBMS software and database objects must be removed.', 'cat2', 'CCI-000381', 'DROP EXTENSION for any contrib module that is not required.'],
  ['pg_patched', 'Security-relevant software updates to PostgreSQL must be installed within the directed time period.', 'cat2', 'CCI-002605', 'Upgrade to the latest minor release of the installed major version.', 'hot'],
  ['pg_offload_audit', 'PostgreSQL must off-load audit data to a separate log management facility.', 'cat2', 'CCI-001851', 'Ship logs to the central log facility (log_destination = syslog or a sidecar).', 'run'],
  ['pg_max_connections', 'PostgreSQL must limit the number of concurrent sessions to an organization-defined number.', 'cat3', 'CCI-000054', 'Set max_connections (and per-role CONNECTION LIMIT) to the organization-defined value.'],
  ['pg_log_timezone_utc', 'PostgreSQL must record time stamps in audit records that can be mapped to UTC.', 'cat3', 'CCI-001890', 'Set log_timezone = UTC.'],
  ['pg_time_sync', 'PostgreSQL must synchronize its clock with the authoritative time source.', 'cat3', 'CCI-001891', 'Synchronize the host clock with the DoD-authoritative time source.', 'run'],
  ['pg_mitm', 'PostgreSQL must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks.', 'cat2', 'CCI-001184', 'Use verify-full client certificates (clientcert=verify-full) on hostssl lines.', 'hot'],
  ['pg_install_account', 'The PostgreSQL software installation account must be restricted to authorized users.', 'cat2', 'CCI-001499', 'Restrict ownership of the PostgreSQL binaries to root/postgres and remove shell access for other accounts.'],
];

interface BenchSeed {
  id: string;
  title: string;
  version: string;
  source: 'disa' | 'ssg';
  profileId: string;
  rules: ScapRule[];
  content: string;
  url: string;
}

function rules(seeds: RuleSeed[], vBase: number, ruleId: (slug: string, v: number) => string): ScapRule[] {
  return seeds.map(([slug, title, severity, cci, fixText], i) => {
    const v = vBase + i * 3;
    return { ruleId: ruleId(slug, v), stigId: `V-${v}`, cci: [cci], severity, result: 'pass', title, fixText };
  });
}

export const SCAP_BENCHMARKS: BenchSeed[] = [
  {
    id: 'disa-rhel9',
    title: 'Red Hat Enterprise Linux 9 STIG',
    version: 'V2R5',
    source: 'disa',
    profileId: 'xccdf_mil.disa.stig_profile_MAC-1_Classified',
    rules: rules(OS_RULES, 257777, (_s, v) => `SV-${v}r${925318 + v - 257777}_rule`),
    content: 'U_RHEL_9_V2R5_STIG_SCAP_1-3_Benchmark.zip',
    url: 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R5_STIG_SCAP_1-3_Benchmark.zip',
  },
  {
    id: 'ssg-ubuntu2204',
    title: 'Canonical Ubuntu 22.04 LTS STIG (ComplianceAsCode)',
    version: '0.1.76',
    source: 'ssg',
    profileId: 'xccdf_org.ssgproject.content_profile_stig',
    rules: rules(OS_RULES, 260469, (slug) => `xccdf_org.ssgproject.content_rule_${slug}`),
    content: 'ssg-ubuntu2204-ds.xml',
    url: 'https://github.com/ComplianceAsCode/content/releases/download/v0.1.76/scap-security-guide-0.1.76.zip',
  },
  {
    id: 'disa-postgresql15',
    title: 'PostgreSQL 15 STIG',
    version: 'V1R2',
    source: 'disa',
    profileId: 'xccdf_mil.disa.stig_profile_MAC-2_Sensitive',
    rules: rules(PG_RULES, 261857, (_s, v) => `SV-${v}r${961002 + v - 261857}_rule`),
    content: 'U_PostgreSQL_15_V1R2_STIG_SCAP_1-3_Benchmark.zip',
    url: 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_PostgreSQL_15_V1R2_STIG_SCAP_1-3_Benchmark.zip',
  },
];
// the SSG content keeps the slug but not every rule carries a V-id cross-reference
for (const i of [26, 28]) SCAP_BENCHMARKS[1].rules[i].stigId = null;

/** image ref → benchmarks, failure rate, rootfs fidelity */
const ASSIGN: Record<string, { benchmarks: string[]; failRate: number; degraded?: boolean }> = {
  'quay.io/keycloak/keycloak:26.0.5': { benchmarks: ['disa-rhel9'], failRate: 0.12 },
  'docker.io/calico/node:v3.28.1': { benchmarks: ['disa-rhel9'], failRate: 0.3, degraded: true },
  'quay.io/projectquay/clair:4.9.0': { benchmarks: ['disa-rhel9'], failRate: 0.08 },
  'localhost:32000/checkmaite-frontend:latest': { benchmarks: ['ssg-ubuntu2204'], failRate: 0.4 },
  'quay.io/jupyterhub/k8s-hub:4.0.0': { benchmarks: ['ssg-ubuntu2204'], failRate: 0.2 },
  'localhost:32000/security-posture-api:4c1e9a2': { benchmarks: ['ssg-ubuntu2204', 'disa-postgresql15'], failRate: 0.1 },
  'docker.io/bitnami/postgresql:16.4.0-debian-12-r2': { benchmarks: ['disa-postgresql15'], failRate: 0.25 },
  'docker.io/library/postgres:16-alpine': { benchmarks: ['disa-postgresql15'], failRate: 0.45 },
};

const WEIGHT: Record<ScapCat, number> = { cat1: 10, cat2: 4, cat3: 1 };

interface Evaluated {
  bench: BenchSeed;
  rules: ScapRule[];
  degraded: boolean;
  checkedAt: string;
}

function summarise(list: ScapRule[]) {
  const n = (r: string) => list.filter((x) => x.result === r).length;
  const evaluated = list.filter((x) => x.result === 'pass' || x.result === 'fail');
  const total = evaluated.reduce((a, x) => a + WEIGHT[x.severity], 0);
  const failed = evaluated.filter((x) => x.result === 'fail').reduce((a, x) => a + WEIGHT[x.severity], 0);
  const open = (c: ScapCat) => list.filter((x) => x.result === 'fail' && x.severity === c).length;
  return {
    pass: n('pass'),
    fail: n('fail'),
    notapplicable: n('notapplicable'),
    notchecked: n('notchecked'),
    error: n('error'),
    score: total ? Math.round(1000 * (1 - failed / total)) / 10 : null,
    cat1Open: open('cat1'),
    cat2Open: open('cat2'),
    cat3Open: open('cat3'),
  };
}

export const STIG_RESULTS = new Map<string, Evaluated[]>();
for (const image of images) {
  const a = ASSIGN[image.ref];
  if (!a) continue;
  STIG_RESULTS.set(
    image.id,
    a.benchmarks.map((id) => {
      const bench = SCAP_BENCHMARKS.find((b) => b.id === id) as BenchSeed;
      const checkedAt = iso((2 + Math.floor(rand() * 4)) * HOUR);
      const evaluated = bench.rules.map((r, i): ScapRule => {
        const kind = (bench.id === 'disa-postgresql15' ? PG_RULES : OS_RULES)[i][5];
        let result: ScapResult;
        if (kind === 'run') result = 'notchecked';
        else if (kind === 'na') result = 'notapplicable';
        else if (a.degraded && i === 8) result = 'error';
        else result = rand() < a.failRate * (kind === 'hot' ? 2.4 : 0.6) ? 'fail' : 'pass';
        return { ...r, result, checkedAt };
      });
      return { bench, rules: evaluated, degraded: Boolean(a.degraded), checkedAt };
    }),
  );
}

export function imageStigBrief(imageId: string): ImageStigBrief | null {
  const list = STIG_RESULTS.get(imageId);
  if (!list) return null;
  const all = list.flatMap((e) => e.rules);
  const s = summarise(all);
  return { score: s.score, benchmarks: list.length, pass: s.pass, fail: s.fail, cat1Open: s.cat1Open, cat2Open: s.cat2Open, cat3Open: s.cat3Open };
}

const RESULT_ORDER: Record<string, number> = { fail: 0, error: 1, pass: 2, notchecked: 3, notapplicable: 4 };

/** `GET /images/{id}/stig` with `page/pageSize/result/severity/q` applied to every benchmark's rules. */
export function imageStigResponse(imageId: string, params: URLSearchParams): ImageStig {
  const list = STIG_RESULTS.get(imageId);
  if (!list) return { status: 'notApplicable', benchmarks: [], reason: 'No SCAP content matches this image (os-release and product probes found no applicable benchmark).' };
  const results = params.get('result')?.split(',').filter(Boolean);
  const sevs = params.get('severity')?.split(',').filter(Boolean);
  const q = params.get('q')?.toLowerCase();
  const page = Math.max(1, Number(params.get('page') ?? 1) || 1);
  const pageSize = Math.min(500, Math.max(1, Number(params.get('pageSize') ?? 50) || 50));
  const only = params.get('benchmark');
  const benchmarks: ImageStigBenchmark[] = list.filter((e) => !only || e.bench.id === only).map((e) => {
    const filtered = e.rules
      .filter(
        (r) =>
          (!results?.length || results.includes(String(r.result))) &&
          (!sevs?.length || sevs.includes(r.severity)) &&
          (!q || [r.title, r.ruleId, r.stigId ?? '', ...r.cci].some((x) => x.toLowerCase().includes(q))),
      )
      .sort((x, y) => (RESULT_ORDER[String(x.result)] ?? 9) - (RESULT_ORDER[String(y.result)] ?? 9) || x.severity.localeCompare(y.severity) || x.ruleId.localeCompare(y.ruleId));
    return {
      benchmarkId: e.bench.id,
      title: e.bench.title,
      version: e.bench.version,
      source: e.bench.source,
      profileId: e.bench.profileId,
      summary: { benchmark: e.bench.id, profile: e.bench.profileId, ...summarise(e.rules), rootfsFidelity: e.degraded ? 'degraded' : 'full', evaluatedAt: e.checkedAt },
      rules: filtered.slice((page - 1) * pageSize, page * pageSize),
      rulesTotal: filtered.length,
      page,
      pageSize,
    };
  });
  const degraded = list.some((e) => e.degraded);
  // mirrors api/src/posture/routers/stig.py image_stig (+ RootfsResult.as_dict)
  return {
    status: 'evaluated',
    benchmarks,
    rootfs: { fidelity: degraded ? 'degraded' : 'full', layers: 7, files: 18_412, droppedXattrs: degraded ? 214 : 0, skippedDevices: 0, unsafeEntries: 0, notes: degraded ? ['file capabilities could not be restored (security.capability)'] : [] },
  } as ImageStig;
}

function evaluationsOf(benchId: string) {
  return [...STIG_RESULTS.entries()].flatMap(([imageId, list]) => list.filter((e) => e.bench.id === benchId).map((e) => ({ imageId, e })));
}

/** `/stig/benchmarks`: evaluated benchmarks plus content that applies to no image (`id: null`). */
export function stigBenchmarkCatalogue(): StigBenchmark[] {
  return [
    ...stigBenchmarkRollup(),
    { id: null as unknown as string, title: 'Red Hat Enterprise Linux 8 STIG (ComplianceAsCode)', version: '0.1.76', source: 'ssg', imagesEvaluated: 0, pass: 0, fail: 0 },
  ];
}

/** Per-benchmark rollup (`/compliance/stig` `product.benchmarks`). */
export function stigBenchmarkRollup(): StigBenchmark[] {
  return SCAP_BENCHMARKS.map((b) => {
    const evals = evaluationsOf(b.id);
    const s = summarise(evals.flatMap(({ e }) => e.rules));
    return {
      id: b.id,
      title: b.title,
      version: b.version,
      source: b.source,
      profileId: b.profileId,
      imagesEvaluated: evals.length,
      pass: s.pass,
      fail: s.fail,
      notapplicable: s.notapplicable,
      notchecked: s.notchecked,
      cat1Open: s.cat1Open,
      cat2Open: s.cat2Open,
      cat3Open: s.cat3Open,
    };
  });
}

/** `GET /stig/benchmarks/{id}/rules` rows; mirrors the API (`failing[]` only lists failing images). */
export function stigBenchmarkRules(benchId: string): Array<StigBenchmarkRule & { failing: Array<{ imageId: string; ref: string }> }> | null {
  const bench = SCAP_BENCHMARKS.find((b) => b.id === benchId);
  if (!bench) return null;
  const evals = evaluationsOf(benchId);
  const refs = new Map(images.map((i) => [i.id, i.ref]));
  return bench.rules
    .map((r) => {
      const per = evals.map(({ imageId, e }) => ({ imageId, ref: refs.get(imageId) ?? imageId, result: String(e.rules.find((x) => x.ruleId === r.ruleId)?.result ?? 'unknown') }));
      return {
        ruleId: r.ruleId,
        stigId: r.stigId,
        cat: r.severity,
        title: r.title,
        cci: r.cci,
        fixText: r.fixText,
        failingImages: per.filter((p) => p.result === 'fail').length,
        passingImages: per.filter((p) => p.result === 'pass').length,
        otherImages: per.filter((p) => p.result !== 'fail' && p.result !== 'pass').length,
        failing: per.filter((p) => p.result === 'fail').map(({ imageId, ref }) => ({ imageId, ref })),
        images: [],
      };
    })
    .sort((a, b) => b.failingImages - a.failingImages || a.cat.localeCompare(b.cat) || a.ruleId.localeCompare(b.ruleId));
}

export function stigRollup(): StigRollup {
  const current = images.filter((i) => i.running);
  const evaluated = current.filter((i) => STIG_RESULTS.has(i.id));
  const all = evaluated.flatMap((i) => (STIG_RESULTS.get(i.id) ?? []).flatMap((e) => e.rules));
  const s = summarise(all);
  // coverage in percent, as the API serves it
  return {
    evaluated: evaluated.length,
    pass: s.pass,
    fail: s.fail,
    cat1Open: s.cat1Open,
    cat2Open: s.cat2Open,
    cat3Open: s.cat3Open,
    coverage: current.length ? Math.round((1000 * evaluated.length) / current.length) / 10 : null,
    notApplicable: current.length - evaluated.length,
    noContent: 0,
    errors: 0,
    pending: 0,
    images: current.length,
    score: s.score,
  };
}

const CONTENT_FETCHED = iso(20 * HOUR);

const SOURCE_NAME: Record<string, string> = { 'disa-rhel9': 'disa-rhel9', 'ssg-ubuntu2204': 'ssg', 'disa-postgresql15': 'disa-postgresql15' };
/** `scap` scanner `content[]` (api/src/posture/routers/stig.py scap_scanner_entry). */
export const scapContentVersions: Array<ScapContentVersion & { file: string }> = SCAP_BENCHMARKS.map((b) => ({
  name: b.title,
  file: b.content,
  title: b.title,
  version: b.version,
  source: b.source,
  sourceName: SOURCE_NAME[b.id],
  benchmarkId: b.id,
  fetchedAt: CONTENT_FETCHED,
  rules: b.rules.length,
}));

export const scapScannerHealth: ScannerHealth & { content: typeof scapContentVersions } = {
  name: 'scap',
  version: '1.3.10',
  dbUpdatedAt: CONTENT_FETCHED,
  healthy: true,
  lastError: null,
  content: scapContentVersions,
};

export const defaultScapSettings: ScapSettings = {
  preferDisa: true,
  timeoutSeconds: 900,
  sources: [
    // the API's ScapSource: {name, kind, url, sha256, include[]}; versions come from the scap scanner's content[]
    { name: 'ssg', kind: 'ssg', url: SCAP_BENCHMARKS[1].url, sha256: 'b6c1f0a4e2d94f3f1e0c8a7b5d2e9c4a1f7b3d6e8c0a2f4b9d1e3c5a7f9b2d4e6', include: ['ssg-ubuntu2204-ds.xml'] },
    { name: 'disa-rhel9', kind: 'disa', url: SCAP_BENCHMARKS[0].url, sha256: '3f9a2c7e1b5d8f0a4c6e2b9d7f1a3c5e8b0d2f4a6c8e1b3d5f7a9c2e4b6d8f0a1', include: [] },
    { name: 'disa-postgresql15', kind: 'disa', url: SCAP_BENCHMARKS[2].url, sha256: '7d2e4f6a8c0b1d3e5f7a9c2b4d6e8f0a1c3e5b7d9f2a4c6e8b0d1f3a5c7e9b2d4', include: [] },
  ],
};
