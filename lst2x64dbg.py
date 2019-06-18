#!/usr/bin/env python3
"""Extract labels from IDA .lst and export to x64dbg database.

This script extracts all the labels found in the LST file that is given as
the script's single argument. An x64dbg database is created in the current
directory based on the extracted labels.

Example:

    $ python3 lst2x64dbg.py sample.lst

Todo:
    * Convert to package with console script
"""
import argparse
import copy
import json
import operator
import pathlib
import re
import sys

parser = argparse.ArgumentParser(description='Extract labels from IDA .lst file and export x64dbg database.')
parser.add_argument('lst', metavar='LST', help='Filename or path of target LST file.')
parser.add_argument('-p', '--pretty', action='store_true', help='Pretty print the database JSON.')
parser.add_argument('-m', '--module', help='Specify the module name.')
args = parser.parse_args()

lst_file = pathlib.Path(args.lst)
if not lst_file.exists():
    sys.exit('ERROR: File `{}` does not exist'.format(lst_file.name))

with open(lst_file, 'r') as fh:
    lst_data = fh.read()

match = re.search('Imagebase +: (?P<imagebase>[0-9A-F]+$)', lst_data, flags=re.M)
if not match:
    sys.exit('ERROR: Imagebase not found')
imagebase = int(match.group('imagebase'), 16)

if args.module:
    module_name = args.module
else:
    module_name = '{}.exe'.format(lst_file.stem)

public = re.findall(r'^.+:(?P<offset>[0-9A-F]{8}) +public +(?P<label>\w+)$', lst_data, flags=re.M | re.A)
proc_near = re.findall(r'^.+:(?P<offset>[0-9A-F]{8}) +(?P<label>\w+) +proc near.*$', lst_data, flags=re.M | re.A)
collapsed = re.findall(r'^.+:(?P<offset>[0-9A-F]{8}) +; +\[\d+ BYTES: COLLAPSED FUNCTION (?P<label>[\w()]+)\. PRESS CTRL-NUMPAD\+ TO EXPAND\].*$', lst_data, flags=re.M | re.A)

labels_raw = set(public) | set(proc_near) | set(collapsed)

labels = list()
for address, label in labels_raw:
    if re.match('sub_[0-9A-F]{8}', label):
        continue
    stripped = address.lstrip('0')
    hex_int = int(stripped, 16)
    label_entry = {'module': module_name,
                   'address': hex_int - imagebase,
                   'manual': False,
                   'text': re.sub(r'\W', '_', label, flags=re.A)}
    labels.append(label_entry)

labels = sorted(labels, key=operator.itemgetter('address'))
for label in labels:
    label['address'] = '0x{}'.format(hex(label['address'])[2:].upper())

x64dbg_db = {'labels': labels}

here = pathlib.Path.cwd()
x64dbg_db_file = here.joinpath('{}.dd32'.format(lst_file.stem))

if x64dbg_db_file.exists():
    with open(x64dbg_db_file, 'r') as fh:
        x64dbg_db_raw = fh.read()
    x64dbg_db_old = json.loads(x64dbg_db_raw)['labels']

    x64dbg_db_new = copy.copy(x64dbg_db_old)

    for entry_outer in x64dbg_db['labels']:
        exists = False
        for entry_inner in x64dbg_db_old:
            if entry_outer['address'] == entry_inner['address']:
                exists = True
        if not exists:
            x64dbg_db_new.append(entry_outer)

    x64dbg_db = {'labels': x64dbg_db_new}

if args.pretty:
    x64dbg_db_str = json.dumps(x64dbg_db, sort_keys=True, indent=4)
else:
    x64dbg_db_str = json.dumps(x64dbg_db)

with open(x64dbg_db_file, 'w') as fh:
    fh.write(x64dbg_db_str)

print('Exported x64dbg database: {}'.format(x64dbg_db_file.name))
if args.module:
    print('Module name: {}'.format(args.module))
sys.exit()
