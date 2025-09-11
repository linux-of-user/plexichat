import os, filecmp
from pathlib import Path

core_dir = Path('core')
src_dir = Path('src/plexichat/core')

core_files = {p.relative_to(core_dir).as_posix(): p for p in core_dir.rglob('*') if p.is_file()}
src_files = {p.relative_to(src_dir).as_posix(): p for p in src_dir.rglob('*') if p.is_file()}

only_core = sorted(set(core_files) - set(src_files))
only_src = sorted(set(src_files) - set(core_files))
common = sorted(set(core_files) & set(src_files))

diff = []
same = []
for rel in common:
    c = core_files[rel]
    s = src_files[rel]
    try:
        if filecmp.cmp(c, s, shallow=False):
            same.append(rel)
        else:
            diff.append(rel)
    except Exception as e:
        diff.append(rel)

print('ONLY_IN_CORE', len(only_core))
for f in only_core:
    print(f)
print('ONLY_IN_SRC', len(only_src))
for f in only_src:
    print(f)
print('DIFF_COUNT', len(diff))
for f in diff:
    print(f)