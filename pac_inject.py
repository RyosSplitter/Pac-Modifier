"""Replace an existing SVR PSP DPK8 member and synchronise its exact ARC table."""
import argparse
import hashlib
import json
from pathlib import Path


def parse(data):
    if data[:4] != b'DPK8' or len(data) < 16384:
        raise ValueError('Expected a DPK8 archive with a 16 KiB header')
    cursor, records = 2048, []
    while cursor < 16384 and data[cursor:cursor + 4] != bytes(4):
        folder = data[cursor:cursor + 4]
        count = (int.from_bytes(data[cursor + 4:cursor + 6], 'little') & 0x3fff) // 3
        if not count:
            raise ValueError('Invalid directory count')
        cursor += 8
        for _ in range(count):
            if cursor + 12 > 16384:
                raise ValueError('Table exceeds header')
            name = data[cursor:cursor + 8]
            offset = int.from_bytes(data[cursor + 8:cursor + 10], 'little')
            size = int.from_bytes(data[cursor + 10:cursor + 12], 'little')
            start = 16384 + offset * 2048
            if start + size * 256 > len(data):
                raise ValueError('Member extends beyond archive')
            records.append((folder, name, cursor, start, size * 256))
            cursor += 12
    if cursor - 2048 != int.from_bytes(data[4:8], 'little'):
        raise ValueError('Header table length mismatch')
    if int.from_bytes(data[8:12], 'little') != len(data) - 16384:
        raise ValueError('Header payload length mismatch')
    return records, cursor


def inject(ch, arc, replacement, member):
    records, end = parse(ch)
    targets = [r for r in records if r[1] == member.encode('ascii')]
    if len(targets) != 1:
        raise ValueError('Member must match exactly once')
    target = targets[0]
    table = ch[2048:end]
    matches = [i for i in range(4, len(arc) - len(table) + 1, 2)
               if arc[i:i + len(table)] == table and arc[i - 4:i - 2] == b'\xff\xff'
               and (i + len(table) == len(arc) or arc[i + len(table):i + len(table) + 2] == b'\xff\xff')]
    if len(matches) != 1:
        raise ValueError('ARC must contain exactly one complete matching table')
    if replacement[:4] != b'PAC ':
        raise ValueError('Replacement must be a nested PAC')
    start, old_size = target[3:5]
    old_span = (old_size + 2047) // 2048 * 2048
    new_span = (len(replacement) + 2047) // 2048 * 2048
    for record in records:
        if record != target and record[3] < start + old_span and record[3] + record[4] > start:
            raise ValueError('Target allocation overlaps another member')
    delta = new_span - old_span
    out = bytearray(ch[:start] + replacement + bytes(new_span - len(replacement)) + ch[start + old_span:])
    out[8:12] = (len(out) - 16384).to_bytes(4, 'little')
    for record in records:
        pos = record[2]
        if record == target:
            out[pos + 10:pos + 12] = ((len(replacement) + 255) // 256).to_bytes(2, 'little')
        elif record[3] >= start + old_span:
            out[pos + 8:pos + 10] = ((record[3] - 16384 + delta) // 2048).to_bytes(2, 'little')
    arc_pos = matches[0]
    arc_out = arc[:arc_pos] + out[2048:end] + arc[arc_pos + len(table):]
    new_records, _ = parse(out)
    preserved = 0
    for before, after in zip(records, new_records):
        assert before[:2] == after[:2]
        if before == target:
            assert out[after[3]:after[3] + len(replacement)] == replacement
        else:
            assert before[4] == after[4]
            assert ch[before[3]:before[3] + before[4]] == out[after[3]:after[3] + after[4]]
            preserved += 1
    assert arc_out[:arc_pos] == arc[:arc_pos]
    assert arc_out[arc_pos + len(table):] == arc[arc_pos + len(table):]
    assert arc_out[arc_pos:arc_pos + len(table)] == out[2048:end]
    report = dict(member=member, replacement_bytes=len(replacement), replacement_sha256=hashlib.sha256(replacement).hexdigest(), unchanged_members_verified=preserved, sector_delta=delta // 2048, arc_table_offset=arc_pos, original_ch_bytes=len(ch), output_ch_bytes=len(out), arc_bytes=len(arc_out))
    return bytes(out), bytes(arc_out), report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ch', type=Path, required=True)
    parser.add_argument('--arc', type=Path, required=True)
    parser.add_argument('--replacement', type=Path, required=True)
    parser.add_argument('--member', default='00010201')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    ch, arc, report = inject(args.ch.read_bytes(), args.arc.read_bytes(), args.replacement.read_bytes(), args.member)
    args.output.mkdir(parents=True, exist_ok=True)
    paths = [args.output / n for n in ['ch.pac', 'plistpsp.arc', 'verification.json']]
    if any(p.exists() for p in paths):
        raise FileExistsError('Output exists; select an empty output directory')
    paths[0].write_bytes(ch)
    paths[1].write_bytes(arc)
    paths[2].write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
