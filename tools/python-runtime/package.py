#!/usr/bin/env python3
"""Fetch checksum-pinned redistributable Python builds into agent downloads.

Only the build machine contacts upstream. Endpoints install from their own
control plane, so fleet installation also works with restricted Internet access.
"""
import gzip
import hashlib
import json
import pathlib
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

def unused(name):
    """pip, its launchers and ensurepip's bundled wheel.

    Endpoints run this interpreter with -I -S, so site-packages is never on
    the path, and sensors are written against the standard library. pip's
    vendored copies (urllib3, msgpack, ...) would only be something for
    vulnerability scanners on every endpoint to flag.
    """
    parts = [p.lower() for p in pathlib.PurePosixPath(name).parts]
    if 'site-packages' in parts:
        rest = parts[parts.index('site-packages') + 1:]
        if rest and rest[0].startswith('pip'):
            return True
    if len(parts) >= 2 and parts[-2] in ('bin', 'scripts') and re.fullmatch(r'pip[0-9.]*(\.exe)?', parts[-1]):
        return True
    return '_bundled' in parts and parts[-1].endswith('.whl')


def safe(member):
    path = pathlib.PurePosixPath(member.name)
    if path.is_absolute() or '..' in path.parts or path.parts[0] != 'python':
        raise RuntimeError('Unexpected Python archive path')


manifest = json.loads(pathlib.Path(__file__).with_name('manifest.json').read_text())
out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else 'bin/agents')
out.mkdir(parents=True, exist_ok=True)
for target, spec in manifest['targets'].items():
    if len(sys.argv) > 2 and target not in sys.argv[2:]:
        continue
    ext = '.zip' if target.startswith('windows-') else '.tar.gz'
    dest = out / ('mustra-python-' + target + ext)
    checksum = dest.with_name(dest.name + '.sha256')
    if dest.exists() and checksum.exists() and hashlib.sha256(dest.read_bytes()).hexdigest() == checksum.read_text().strip():
        # Source digest/version are recorded separately so a pin update invalidates the cache.
        pin = dest.with_name(dest.name + '.source')
        if pin.exists() and pin.read_text() == spec['sha256']:
            continue
    print('Packaging Python', manifest['version'], target, flush=True)
    with tempfile.TemporaryDirectory() as tmp:
        archive = pathlib.Path(tmp) / 'source.tar.gz'
        with urllib.request.urlopen(spec['url'], timeout=120) as response, archive.open('wb') as stream:
            shutil.copyfileobj(response, stream)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != spec['sha256']:
            raise RuntimeError('Python archive checksum mismatch: ' + target)
        if ext == '.zip':
            # Windows installers use Expand-Archive. Deterministic ZIP metadata
            # keeps the checksum independent of the build machine and timezone.
            with tarfile.open(archive) as tar, zipfile.ZipFile(dest, 'w', zipfile.ZIP_DEFLATED) as z:
                for member in sorted(tar.getmembers(), key=lambda m: m.name):
                    safe(member)
                    if unused(member.name):
                        continue
                    if member.isfile():
                        info = zipfile.ZipInfo(member.name, (2020, 1, 1, 0, 0, 0))
                        info.compress_type = zipfile.ZIP_DEFLATED
                        z.writestr(info, tar.extractfile(member).read())
                    elif not member.isdir():
                        raise RuntimeError('Unexpected link in Windows Python archive')
        else:
            # Repacked in upstream order with upstream metadata and a fixed
            # gzip header, so the checksum depends only on the pinned source.
            with tarfile.open(archive) as tar, dest.open('wb') as raw, \
                    gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as gz, \
                    tarfile.open(fileobj=gz, mode='w', format=tarfile.GNU_FORMAT) as repacked:
                for member in tar.getmembers():
                    safe(member)
                    if unused(member.name):
                        continue
                    repacked.addfile(member, tar.extractfile(member) if member.isfile() else None)
        checksum.write_text(hashlib.sha256(dest.read_bytes()).hexdigest() + '\n')
        dest.with_name(dest.name + '.source').write_text(spec['sha256'])
