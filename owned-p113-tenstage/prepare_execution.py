"""Prevalidate this owned source packet, then copy absent passive/science roots.

Never launches a driver/test/build/audit or edits original scientific source.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import stat
import tarfile

EXPECTED = '8ce64167539a55d18803bcc1de9a2de5d1e8271112f7b26e387905e7957e17bd'
PREFIXES = ('artifact/tosem/results', 'artifact/fse/results', 'artifact/results',
            'artifact/logs', 'artifact/scientific-check-output',
            'artifact/scalar-regression-output', 'artifact/_fresh-science',
            'artifact/fresh-native-evidence', 'paper/generated')
EXACT = ('artifact/docs/AUDIT_REPORT.md',)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fs(path):
    path = Path(os.path.abspath(path))
    return Path('\\\\?\\'+str(path)) if os.name == 'nt' else path


def plain(path):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and
            not getattr(info, 'st_file_attributes', 0)&0x400 and
            (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)), 'linked/special path')


def absent(path):
    path = Path(os.path.abspath(path))
    require(not path.exists(), 'existing output preserved')
    require(path.parent.is_dir(), 'output parent must exist')
    for ancestor in (path.parent, *path.parent.parents):
        plain(fs(ancestor))
    return path


def excluded(name):
    return name in EXACT or any(name == p or name.startswith(p+'/') for p in PREFIXES)


def inventory(root):
    root = fs(root)
    result = {}
    for path in sorted(root.rglob('*')):
        plain(path)
        if path.is_file():
            name = path.relative_to(root).as_posix()
            if not excluded(name):
                result[name] = sha(path.read_bytes())
    return result


def prepare(packet, out):
    plain(fs(packet))
    require(packet.stat().st_size <= 8*1024*1024 and sha(packet.read_bytes()) == EXPECTED,
            'exact source archive/size guard')
    out = absent(out)
    require(not packet.resolve().is_relative_to(out), 'archive/output overlap')
    payload = {}
    total = 0
    with tarfile.open(packet, 'r:gz') as archive:
        for item in archive:
            path = PurePosixPath(item.name)
            require(item.isfile() and not path.is_absolute() and
                    item.name == path.as_posix() and '\\' not in item.name and ':' not in item.name
                    and all(p not in ('', '.', '..') for p in path.parts), 'unsafe tar member')
            require(item.name not in payload and item.size >= 0, 'duplicate/invalid tar member')
            total += item.size
            require(total <= 128*1024*1024, 'uncompressed packet bound')
            payload[item.name] = archive.extractfile(item).read()
            require(len(payload[item.name]) == item.size, 'truncated tar payload')
    manifest = json.loads(payload['meta/source-manifest.json'])
    require(manifest['schema'] == 'p113-owned-tenstage-source-packet-v1', 'manifest schema')
    members = manifest['source_members']
    require(set(payload) == set(members)|{'meta/source-manifest.json'} and
            len(members) == 1481, 'complete source member set')
    for name, row in members.items():
        require(name.startswith('P113/') and len(payload[name]) == row['bytes'] and
                sha(payload[name]) == row['sha256'], 'source member guard: '+name)
    for name, digest in manifest['six_unchanged_longpath_certificates'].items():
        require(sha(payload['P113/'+name]) == digest, 'original certificate guard')
    # No output exists before all members, hashes and plain destinations validate.
    fs(out).mkdir()
    for name, data in payload.items():
        target = fs(out/'retained'/name)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
    immutable = {}
    exclusions = []
    for name in members:
        rel = name.removeprefix('P113/')
        if excluded(rel):
            exclusions.append(rel)
            continue
        target = fs(out/'execution/P113'/rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(payload[name])
        immutable[rel] = members[name]['sha256']
    fs(out/'execution/P113/paper/generated').mkdir()
    require(inventory(out/'execution/P113') == immutable, 'execution copy bytes')
    for prefix in PREFIXES[:-1]:
        require(not fs(out/'execution/P113'/prefix).exists(), 'old generated output leaked')
    record = dict(source_archive_sha256=EXPECTED, immutable_execution_files=immutable,
                  excluded_output_prefixes=PREFIXES, excluded_output_files=EXACT,
                  exact_excluded_members=sorted(exclusions),
                  source_manifest_sha256=sha(payload['meta/source-manifest.json']),
                  scope='Private absent copy only; no scientific execution, test or positive receipt.')
    with fs(out/'preparation.json').open('x', encoding='utf-8') as stream:
        json.dump(record, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps(dict(prepared=True, source_members=len(members),
                         immutable_execution_files=len(immutable), excluded_output_members=len(exclusions),
                         scientific_execution=False)))


def verify(out):
    record = json.loads(fs(out/'preparation.json').read_text(encoding='utf-8'))
    require(record['source_archive_sha256'] == EXPECTED and
            tuple(record['excluded_output_prefixes']) == PREFIXES and
            tuple(record['excluded_output_files']) == EXACT, 'preparation identity')
    require(inventory(out/'execution/P113') == record['immutable_execution_files'],
            'immutable execution source/input changed')
    print(json.dumps(dict(immutable_source_unchanged=True,
                         scope='Input byte check only, not scientific/PDF audit.')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('prepare', 'verify'))
    parser.add_argument('--packet', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.mode == 'prepare':
        require(args.packet is not None, 'source packet required')
        prepare(args.packet, args.out)
    else:
        verify(args.out)


if __name__ == '__main__':
    main()
