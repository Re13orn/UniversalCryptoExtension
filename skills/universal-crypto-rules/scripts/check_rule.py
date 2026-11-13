#!/usr/bin/env python3
"""Validate UCE rules and replay fixtures with real Java classes, without live config or network."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    location = parser.add_mutually_exclusive_group(required=True)
    location.add_argument('--project', type=Path, help='UniversalCryptoExtension project')
    location.add_argument('--jar', type=Path, help='Standalone distribution JAR; defaults to packaged runtime')
    parser.add_argument('--rules', required=True, type=Path)
    parser.add_argument('--fixtures', type=Path)
    parser.add_argument('--runtime', choices=['source', 'packaged'], default=None, help='source uses target/classes; packaged tests exactly the distribution JAR (including its signed nested BC)')
    parser.add_argument('--bc-jar', type=Path, help='Optional extra source classpath entry for legacy builds; current internal engines use embedded BC')
    parser.add_argument('--timeout', type=int, default=90, help='Whole Java probe timeout, in seconds')
    args = parser.parse_args()
    args.runtime = args.runtime or ('packaged' if args.jar else 'source')
    if args.jar and args.runtime != 'packaged':
        parser.error('--jar only supports --runtime packaged; use --project for source mode')
    project = args.project.expanduser().resolve() if args.project else None
    jar = args.jar.expanduser().resolve() if args.jar else project / 'target/universal-crypto-extension-1.0.0.jar'
    classes = project / 'target/classes' if project else None
    if not jar.is_file():
        parser.error('Distribution JAR missing; run ./build.sh or provide --jar')
    if project:
        sources = list((project / 'src/main/java').rglob('*.java')) + [project / 'pom.xml']
        stale = [p.relative_to(project).as_posix() for p in sources if p.exists() and p.stat().st_mtime_ns > jar.stat().st_mtime_ns]
        if stale:
            parser.error('Source/pom is newer than the JAR; run ./build.sh: ' + ', '.join(stale[:5]))
        if args.runtime == 'source':
            if not classes.is_dir(): parser.error('Source mode requires target/classes; run ./build.sh')
            missing_classes = [p for p in sources if p.suffix == '.java' and not (classes / p.relative_to(project / 'src/main/java')).with_suffix('.class').exists()]
            if missing_classes: parser.error('Compiled classes are incomplete; run ./build.sh')
    if args.bc_jar and args.runtime != 'source':
        parser.error('--bc-jar applies only to source mode; packaged mode uses its own nested provider')
    inputs = [args.rules, args.fixtures] if args.fixtures else [args.rules]
    if any(not p.expanduser().resolve().is_file() for p in inputs):
        parser.error('Rules/fixture file does not exist')
    if args.timeout < 1:
        parser.error('--timeout must be positive')
    source = Path(__file__).resolve().with_name('RuleProbe.java')
    if args.runtime == 'source':
        # Current internal engines load their own nested signed BC dependency.
        entries = [str(classes), str(jar)]
        if args.bc_jar:
            bc = args.bc_jar.expanduser().resolve()
            if not bc.is_file():
                parser.error('--bc-jar file does not exist')
            entries.insert(1, str(bc))
        classpath = os.pathsep.join(entries)
    else:
        classpath = str(jar)
    try:
        with tempfile.TemporaryDirectory(prefix='uce-rule-probe-') as temp:
            subprocess.run(['javac', '-encoding', 'UTF-8', '-cp', classpath, '-d', temp, str(source)], check=True, timeout=30)
            command = ['java', '-Djava.awt.headless=true', f'-Duce.probe.runtime={args.runtime}', '-cp', os.pathsep.join([temp, classpath]), 'RuleProbe', str(args.rules.expanduser().resolve())]
            if args.fixtures:
                command += [str(args.fixtures.expanduser().resolve()), str(Path(temp) / 'isolated-config')]
            subprocess.run(command, check=True, timeout=args.timeout)
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f'Rule validation failed: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
