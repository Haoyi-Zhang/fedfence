#!/usr/bin/env python3
"""Opt-in installation of the verified acmart v2.20 source release.

This helper is NOT called by the offline evidence command. It fetches only the
class source/installer, bibliography style, and license, never font files.
Each byte stream is checked against a Git blob identity read from the official
repository at the v2.20 tag on 2026-10-03. No edited class or version spoofing.
"""
from __future__ import annotations
import hashlib, json, shutil, subprocess, sys, tempfile, urllib.request
from pathlib import Path
PAPER=Path(globals().get("MANUSCRIPT_DIR", Path(__file__).resolve().parents[2] / "paper"))
SUPPORT=Path(__file__).resolve().parent
BASE='https://raw.githubusercontent.com/borisveytsman/acmart/v2.20/'
FILES={
 'acmart.dtx':('b60702dcc84dd19b450e1dd9820bc605a16b7e19',306814),
 'acmart.ins':('d17dc066fd7f86023b4ea0e33aa75aef95b33857',1016),
 'ACM-Reference-Format.bst':('4f607da45ff04d5712f87a7a3308507dab41fac3',94292),
 'LICENSE':('cd58edfc22fdae5433e5d3f3ba2c5d052fe37e83',19040),
}

def main()->int:
    target=PAPER/'vendor/acmart-2.20'
    target.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='acmart-',dir=target.parent) as tmp:
        stage=Path(tmp); records=[]
        for name,(expected,size) in FILES.items():
            request=urllib.request.Request(BASE+name,headers={'User-Agent':'FedFence-template-build/1'})
            with urllib.request.urlopen(request,timeout=30) as response:
                data=response.read(size+1)
            git_sha=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
            if len(data)!=size or git_sha!=expected:
                raise ValueError(f'official source identity mismatch: {name}; refusing installation')
            (stage/name).write_bytes(data)
            records.append(dict(file=name,git_blob_sha1=git_sha,sha256=hashlib.sha256(data).hexdigest(),bytes=len(data)))
        subprocess.run(['latex','-interaction=nonstopmode','-halt-on-error','acmart.ins'],cwd=stage,check=True)
        cls=stage/'acmart.cls'
        if not cls.is_file() or 'v2.20' not in cls.read_text(errors='replace'):
            raise RuntimeError('generated class does not declare v2.20')
        SUPPORT.mkdir(parents=True,exist_ok=True)
        (SUPPORT/'template_installation.json').write_text(json.dumps(dict(repository='borisveytsman/acmart',tag='v2.20',tag_object='742841bea00b99d9f868ba7d7c3e03b4cb72b36e',upstream_checked='2026-10-03',files=records,fonts_distributed=False),indent=2)+'\n')
        if target.exists():
            raise FileExistsError(f'{target} already exists; inspect/remove it explicitly before replacing')
        stage.rename(target)
    print('Verified official class installed at',target)
    return 0

if __name__=='__main__':
    try:raise SystemExit(main())
    except (OSError,ValueError,RuntimeError,subprocess.CalledProcessError) as exc:
        print('Template installation did not complete:',exc,file=sys.stderr)
        raise SystemExit(1)
