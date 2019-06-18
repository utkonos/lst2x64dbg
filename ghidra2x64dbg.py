#!/usr/bin/env python3
"""Extract labels from Ghidra CSV and export to x64dbg database.

This script extracts all the labels found in the CSV file that is given as
the script's single argument. An x64dbg database is created in the current
directory based on the extracted labels. The imagebase value must be supplied.

Example:

    $ python3 ghidra2x64dbg.py -i 400000 sample.csv

Todo:
    * Convert to package with console script
"""
import argparse
import csv
import json
import operator
import pathlib
import re
import sys

parser = argparse.ArgumentParser(description='Extract labels from Ghidra CSV and export to x64dbg database.')
parser.add_argument('csv', metavar='CSV', help='Filename or path of target CSV file.')
parser.add_argument('-i', '--imagebase', help='Specify the imagebase value.', required=True)
parser.add_argument('-p', '--pretty', action='store_true', help='Pretty print the database JSON.')
parser.add_argument('-m', '--module', help='Specify the module name.')
args = parser.parse_args()

csv_file = pathlib.Path(args.csv)
if not csv_file.exists():
    sys.exit('ERROR: File `{}` does not exist'.format(csv_file.name))

if args.module:
    module_name = args.module
else:
    module_name = '{}.exe'.format(csv_file.stem)

labels = list()
with open(csv_file) as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        if re.match(r'External\[[0-9a-f]+\]', row['Location']):
            continue
        stripped = row['Location'].lstrip('0')
        hex_int = int(stripped, 16)
        label = re.sub(r'\W', '_', row['Name'], flags=re.A)
        label_entry = {'module': module_name,
                       'address': hex_int - int(args.imagebase, 16),
                       'manual': False,
                       'text': label}
        labels.append(label_entry)

labels = sorted(labels, key=operator.itemgetter('address'))
for label in labels:
    label['address'] = '0x{}'.format(hex(label['address'])[2:].upper())

x64dbg_db = {'labels': labels}

here = pathlib.Path.cwd()
x64dbg_db_file = here.joinpath('{}.dd32'.format(csv_file.stem))

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
