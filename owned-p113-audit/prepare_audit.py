"""Extract a frozen actual-output/PDF packet, or check the original auditor's writes.

No science, tests, paper build, provider command or network operation is launched.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import stat
import tarfile

EXPECTED = '1b58ac09c5eaa8c361ca3150ddab44e2748f1f36f0a2f33bb884d1471168ff1f'
MANIFEST = 'meta/audit-input-manifest.json'
OUTPUTS = {'P113/artifact/tosem/results/final_audit.json', 'P113/artifact/docs/AUDIT_REPORT.md'}


def require(ok, detail):
    if not ok:
        raise ValueError(detail)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fs(path):
    path = path.resolve()
    return (Path('\\\\?\\'+str(path)) if os.name == 'nt' and
            not str(path).startswith('\\\\?\\') else path)


def plain(path):
    info = fs(path).lstat()
    require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0)&0x400
            and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)), 'linked/special path')


def prepare(packet, out):
    plain(packet)
    require(packet.stat().st_size <= 8*1024*1024 and sha(packet.read_bytes()) == EXPECTED,
            'exact frozen audit input archive')
    out = out.absolute()
    require(not out.exists() and out.parent.is_dir(), 'absent output with existing parent')
    for ancestor in (out.parent, *out.parent.parents):
        plain(ancestor)
    require(not packet.resolve().is_relative_to(out), 'packet/output overlap')
    payload, total = {}, 0
    with tarfile.open(packet, 'r:gz') as archive:
        for item in archive:
            name = PurePosixPath(item.name)
            require(item.isfile() and not name.is_absolute() and item.name == name.as_posix()
                    and '\\' not in item.name and ':' not in item.name
                    and all(p not in ('', '.', '..') for p in name.parts), 'unsafe tar path/type')
            require(item.name not in payload and item.size >= 0, 'duplicate/invalid member')
            total += item.size
            require(total <= 64*1024*1024, 'bounded uncompressed packet')
            data = archive.extractfile(item).read()
            require(len(data) == item.size, 'truncated archive member')
            payload[item.name] = data
    require(len({name.casefold() for name in payload}) == len(payload), 'case-colliding paths')
    manifest = json.loads(payload[MANIFEST])
    members = manifest['members']
    require(manifest['schema'] == 'p113-same-science-audit-input-v1' and
            len(members) == 1239 and set(payload) == set(members)|{MANIFEST}
            and set(manifest['allowed_new_audit_outputs']) == OUTPUTS and not OUTPUTS&set(payload),
            'complete input membership, absent final audit outputs')
    for name, row in members.items():
        require(name.startswith('P113/') and len(payload[name]) == row['bytes']
                and sha(payload[name]) == row['sha256'], 'input byte guard: '+name)
    require(manifest['scientific_reruns'] == 0 and manifest['final_native_audit_performed'] is False
            and manifest['original_job_conclusion'] == 'failure', 'original attempt not relabelled')
    # All content/path/hash checks finish before the first output write.
    fs(out).mkdir()
    for name, data in payload.items():
        target = fs(out/name)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
    print(json.dumps(dict(extracted_files=len(payload), source_packet_sha256=EXPECTED,
                          science_reruns=0, final_audit_performed=False)))


def verify(out, packet):
    plain(packet)
    require(packet.stat().st_size <= 8*1024*1024 and sha(packet.read_bytes()) == EXPECTED,
            'same frozen audit archive for verification')
    with tarfile.open(packet, 'r:gz') as archive:
        frozen_manifest = archive.extractfile(MANIFEST).read()
    require(fs(out/MANIFEST).read_bytes() == frozen_manifest, 'unchanged input manifest')
    manifest = json.loads(frozen_manifest)
    expected = manifest['members']
    names = set()
    for path in fs(out).rglob('*'):
        plain(path)
        if path.is_file():
            name = path.relative_to(fs(out)).as_posix()
            names.add(name)
            if name in expected:
                require(sha(path.read_bytes()) == expected[name]['sha256'], 'input changed: '+name)
    require(names == set(expected)|{MANIFEST}|OUTPUTS, 'only two genuine audit outputs permitted')
    audit = json.loads(fs(out/'P113/artifact/tosem/results/final_audit.json').read_text(encoding='utf-8'))
    require(audit['schema'] == 'fedfence-tosem-final-consistency-audit-v1'
            and audit['passed'] is True and audit['checks']
            and all(row['passed'] is True for row in audit['checks']), 'original final audit must really pass')
    require(audit['implementation_sha256'] == manifest['implementation_sha256']
            and audit['paper']['sha256'] == manifest['pdf_sha256'] and audit['paper']['pages'] == 41,
            'same scientific source and real original-profile PDF')
    print(json.dumps(dict(original_audit_passed=True, checks=len(audit['checks']),
                          paper=audit['paper'], unchanged_input_files=len(expected), science_reruns=0)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('prepare', 'verify'))
    parser.add_argument('--packet', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    require(args.packet is not None, 'packet required')
    if args.mode == 'prepare':
        prepare(args.packet, args.out)
    else:
        verify(args.out, args.packet)


if __name__ == '__main__':
    main()
