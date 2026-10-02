"""Regenerate src/posture/reports/data/stig_mapping.yaml from the official DISA XCCDF files.

Usage (download + unzip the DISA zips first):
    curl -LO https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Kubernetes_V2R6_STIG.zip
    curl -LO https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Container_Platform_V2R4_SRG.zip
    python tests/reports/build_stig_mapping.py <k8s-xccdf.xml> <cp-srg-xccdf.xml> src/posture/reports/data/stig_mapping.yaml

The `EVAL` table below is the hand-maintained part (how each rule is evaluated).
"""
import re, sys, xml.etree.ElementTree as ET, html
import yaml

NS = {'x': 'http://checklists.nist.gov/xccdf/1.1', 'dc': 'http://purl.org/dc/elements/1.1/'}

ALL_CHECKS = ["privileged", "host-namespaces", "host-path", "run-as-root", "privilege-escalation",
              "added-capabilities", "capabilities-not-dropped", "writable-rootfs", "no-resource-limits",
              "no-resource-requests", "mutable-tag", "no-liveness-probe", "no-readiness-probe",
              "automount-sa-token", "seccomp-unconfined", "no-netpol"]

# vulnId -> evaluation
EVAL = {
    # ---- Kubernetes STIG ----
    'V-242437': dict(method='posture', checks=['privileged', 'run-as-root', 'privilege-escalation'],
                     onFail='Open', onPass='Not_Reviewed',
                     note='Evidence-based: running privileged/root/escalating pods show the admission policy does not '
                          'enforce least privilege. The STIG check itself inspects the admission configuration, '
                          'which this tool does not read; a clean result still needs manual review.'),
    'V-254800': dict(method='posture', checks=['privileged', 'host-namespaces', 'host-path', 'run-as-root',
                                              'privilege-escalation', 'added-capabilities', 'seccomp-unconfined'],
                     onFail='Open', onPass='Not_Reviewed',
                     note='Pods violating the Pod Security Standards "restricted" profile are running, so Pod Security '
                          'Admission is not enforcing least privilege for those namespaces. The '
                          '--admission-control-config-file flag itself must be verified manually.'),
    'V-242414': dict(method='posture', checks=['host-namespaces'], onFail='Not_Reviewed', onPass='Not_Reviewed',
                     note='hostPort declarations are not inventoried; pods sharing the host network namespace are '
                          'listed for the reviewer because any port they bind is a host port.'),
    'V-242383': dict(method='inventory', namespaces=['default', 'kube-public', 'kube-node-lease'],
                     onFail='Open', onPass='NotAFinding',
                     note='Evaluated from the pod/workload inventory only; non-pod resources (Services other than '
                          'service/kubernetes, ConfigMaps, ...) in these namespaces are not inventoried.'),
    'V-242417': dict(method='inventory', namespaces=['kube-system', 'kube-public', 'kube-node-lease'],
                     onFail='Not_Reviewed', onPass='NotAFinding',
                     note='Workloads in Kubernetes system namespaces are listed; the reviewer must decide which are '
                          'platform components and which are user pods.'),
    'V-242443': dict(method='vulnerabilities', severities=['critical', 'high'], fixableOnly=True,
                     onFail='Not_Reviewed', onPass='Not_Reviewed',
                     note='The STIG check verifies the Kubernetes version skew policy, which this tool does not '
                          'evaluate. Fixable critical/high image vulnerabilities are listed as supporting IAVM evidence.'),
    # ---- Container Platform SRG ----
    'V-233127': dict(method='posture', checks=['privileged', 'host-namespaces', 'host-path', 'added-capabilities'],
                     onFail='Open', onPass='NotAFinding'),
    'V-233163': dict(method='posture', checks=['run-as-root', 'privilege-escalation', 'capabilities-not-dropped',
                                              'seccomp-unconfined', 'automount-sa-token'],
                     onFail='Open', onPass='NotAFinding'),
    'V-233074': dict(method='posture', checks=['host-namespaces'], onFail='Not_Reviewed', onPass='Not_Reviewed',
                     note='hostPort declarations are not inventoried; host-network pods are listed for review.'),
    'V-270875': dict(method='posture', checks=['no-resource-limits', 'no-resource-requests'],
                     onFail='Open', onPass='NotAFinding'),
    'V-270876': dict(method='posture', checks=['writable-rootfs'], onFail='Open', onPass='NotAFinding'),
    'V-233222': dict(method='posture', checks=['no-resource-limits'], onFail='Open', onPass='Not_Reviewed',
                     note='Resource limits are one DoS control; rate limiting and quotas are not evaluated.'),
    'V-233029': dict(method='posture', checks=['no-netpol'], onFail='Open', onPass='Not_Reviewed',
                     note='A selecting NetworkPolicy exists for every pod; policy content is not evaluated.'),
    'V-233030': dict(method='posture', checks=['no-netpol'], onFail='Open', onPass='Not_Reviewed',
                     note='A selecting NetworkPolicy exists for every pod; policy content is not evaluated.'),
    'V-233065': dict(method='posture', checks=['mutable-tag'], onFail='Open', onPass='Not_Reviewed',
                     note='Mutable tags defeat image verification. Signature verification itself is not evaluated.'),
    'V-233233': dict(method='vulnerabilities', severities=['critical', 'high', 'medium', 'low'], fixableOnly=True,
                     onFail='Open', onPass='NotAFinding'),
    'V-233234': dict(method='vulnerabilities', severities=['critical', 'high', 'medium', 'low'], fixableOnly=True,
                     olderThanDays=30, onFail='Open', onPass='NotAFinding'),
    'V-233275': dict(method='scanner-coverage', maxAgeDays=7, onFail='Open', onPass='NotAFinding'),
    'V-233273': dict(method='posture', checks=ALL_CHECKS, aggregate=True, onFail='Open', onPass='Not_Reviewed',
                     note='Aggregates every workload posture check; host and control-plane configuration is not evaluated.'),
}
SRG_INCLUDE = [k for k in EVAL if k.startswith('V-233') or k.startswith('V-2708')]


def inner(desc, tag):
    m = re.search(rf'<{tag}>(.*?)</{tag}>', desc or '', re.S)
    return html.unescape(m.group(1)).strip() if m else ''


def parse(path, key, include=None):
    root = ET.parse(path).getroot()
    rel = root.find("x:plain-text[@id='release-info']", NS).text
    relnum = re.search(r'Release: (\d+)', rel).group(1)
    ver = root.findtext('x:version', namespaces=NS)
    ref = root.find('x:Group/x:Rule/x:reference', NS)
    bench = dict(
        key=key, stigId=root.get('id'), title=root.findtext('x:title', namespaces=NS),
        version=ver, release=relnum, releaseInfo=rel,
        description=root.findtext('x:description', namespaces=NS),
        referenceIdentifier=ref.findtext('dc:identifier', namespaces=NS) if ref is not None else '',
        source='STIG.DOD.MIL', notice='terms-of-use',
        filename=path.rsplit('/', 1)[1], verified=True,
    )
    rules = []
    for g in root.findall('x:Group', NS):
        vid = g.get('id')
        if include is not None and vid not in include:
            continue
        r = g.find('x:Rule', NS)
        desc = r.findtext('x:description', namespaces=NS)
        sev = r.get('severity')
        ent = dict(
            benchmark=key, vulnId=vid, ruleId=r.get('id'),
            ruleVersion=r.findtext('x:version', namespaces=NS),
            groupTitle=g.findtext('x:title', namespaces=NS),
            ruleTitle=r.findtext('x:title', namespaces=NS),
            severity=sev, cat={'high': 'I', 'medium': 'II', 'low': 'III'}[sev], weight=r.get('weight'),
            ccis=[i.text for i in r.findall('x:ident', NS) if i.get('system', '').endswith('cci')],
            legacyIds=[i.text for i in r.findall('x:ident', NS) if 'legacy' in i.get('system', '')],
            discussion=inner(desc, 'VulnDiscussion'),
            checkContent=(r.find('x:check/x:check-content', NS).text or '').strip(),
            checkContentRef=(r.find('x:check/x:check-content-ref', NS).get('name')
                             if r.find('x:check/x:check-content-ref', NS) is not None else 'M'),
            fixText=(r.findtext('x:fixtext', namespaces=NS) or '').strip(),
            verified=True,
        )
        ev = EVAL.get(vid)
        ent['evaluation'] = ev if ev else dict(method='none')
        rules.append(ent)
    return bench, rules


class Dumper(yaml.SafeDumper):
    pass


def str_rep(d, s):
    if '\n' in s:
        s = '\n'.join(line.rstrip() for line in s.replace('\r\n', '\n').split('\n'))
        return d.represent_scalar('tag:yaml.org,2002:str', s, style='|')
    return d.represent_scalar('tag:yaml.org,2002:str', s)


Dumper.add_representer(str, str_rep)

if len(sys.argv) != 4:
    sys.exit(__doc__)
K8S, SRG, out = sys.argv[1:4]
kb, kr = parse(K8S, 'kubernetes')
sb, sr = parse(SRG, 'container-platform-srg', include=set(SRG_INCLUDE))
sb['subset'] = True
missing = set(EVAL) - {r['vulnId'] for r in kr + sr}
assert not missing, missing
doc = {
    'schemaVersion': 1,
    'generatedFrom': [
        'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Kubernetes_V2R6_STIG.zip',
        'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Container_Platform_V2R4_SRG.zip',
    ],
    'benchmarks': [kb, sb],
    'rules': kr + sr,
}
hdr = """# STIG mapping for nebari-security-posture-pack compliance reports.
#
# GENERATED from the official DISA XCCDF benchmarks listed under `generatedFrom`
# (Kubernetes STIG V2R6, 01 Apr 2026 - all 92 rules; Container Platform SRG V2R4,
# 28 Oct 2025 - only the rules this tool can produce evidence for). Every rule text,
# severity, Rule ID and CCI below is copied verbatim from the XCCDF (`verified: true`).
#
# `evaluation` is ours: how stig.py derives a checklist STATUS for the rule.
#   method: posture          -> Open/onFail when any listed posture check failed
#           vulnerabilities  -> onFail when a matching consensus finding exists
#           inventory        -> onFail when workloads run in the listed namespaces
#           scanner-coverage -> onPass when a scan finished recently with >=1 healthy scanner
#           none             -> always Not_Reviewed (manual / host-level check)
#   onFail / onPass: CKL status to emit (NotAFinding | Open | Not_Reviewed | Not_Applicable)
#   aggregate: true  -> catch-all rule; not cited as "the" STIG rule for an individual check
# Regenerate with the script referenced in docs/REPORTS.md when DISA publishes a new release.
"""
with open(out, 'w') as f:
    f.write(hdr)
    yaml.dump(doc, f, Dumper=Dumper, sort_keys=False, allow_unicode=True, width=1000)
print(len(kr), len(sr))
