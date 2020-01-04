"""lst2x64dbg command line script.

This module contains command line scripts for lst2x64dbg and ghidra2x64dbg.
"""
import argparse
import copy
import csv
import json
import operator
import pathlib
import re
import sys


def _open_input(filename):
    """Check that the input file exists and return pathlib object."""
    here = pathlib.Path().cwd()
    input_path = here.joinpath(filename)
    if not input_path.exists():
        sys.exit('ERROR: File `{}` does not exist'.format(filename))

    return input_path


def _export_db(labels, input_stem, six_four, pretty, module):
    """Export the list of labels to an x64dbg database on disk."""
    labels = sorted(labels, key=operator.itemgetter('address'))
    for label in labels:
        label['address'] = '0x{}'.format(hex(label['address'])[2:].upper())

    x64dbg_db = {'labels': labels}

    extension = '{}.dd64'.format(input_stem) if six_four else '{}.dd32'.format(input_stem)

    here = pathlib.Path.cwd()
    x64dbg_db_file = here.joinpath(extension)

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

    if pretty:
        x64dbg_db_str = json.dumps(x64dbg_db, sort_keys=True, indent=4)
    else:
        x64dbg_db_str = json.dumps(x64dbg_db)

    with open(x64dbg_db_file, 'w') as fh:
        fh.write(x64dbg_db_str)

    print('Exported x64dbg database: {}'.format(x64dbg_db_file.name))
    if module:
        print('Module name: {}'.format(module))
    sys.exit()


def lst2x64dbg():
    """Extract labels from IDA .lst and export to x64dbg database.

    This command extracts all the labels found in the LST file that is given as
    the single argument. An x64dbg database is created in the current directory
    based on the extracted labels.

    Example:

        $ lst2x64dbg sample.lst
    """
    parser = argparse.ArgumentParser(description='Extract labels from IDA .lst file and export x64dbg database.')
    parser.add_argument('lst', metavar='LST', help='Filename or path of target LST file.')
    parser.add_argument('-p', '--pretty', action='store_true', help='Pretty print the database JSON.')
    parser.add_argument('-d', '--dll', action='store_true', help='File is a DLL.')
    parser.add_argument('-m', '--module', help='Specify the module name.')
    parser.add_argument('-r', '--main', help='Add main from radare2.')
    args = parser.parse_args()

    input_path = _open_input(args.lst)

    if args.module:
        module_name = args.module
    else:
        if args.dll:
            module_name = '{}.dll'.format(input_path.stem)
        else:
            module_name = '{}.exe'.format(input_path.stem)

    with open(input_path, 'r') as fh:
        lst_data = fh.read()

    match = re.search('Imagebase +: (?P<imagebase>[0-9A-F]+$)', lst_data, flags=re.M)
    if not match:
        sys.exit('ERROR: Imagebase not found')
    imagebase = int(match.group('imagebase'), 16)
    print('Using imagebase: {}'.format(match.group('imagebase')))

    six_four = re.search(r'Format      : Portable executable for AMD64 \(PE\)', lst_data, flags=re.M)

    public = re.findall(r'^.+:(?P<offset>(?:[0-9A-F]{8}|[0-9A-F]{16})) +public +(?P<label>\w+)$', lst_data, flags=re.M | re.A)
    proc_near = re.findall(r'^.+:(?P<offset>(?:[0-9A-F]{8}|[0-9A-F]{16})) +(?P<label>\w+) +proc near.*$', lst_data, flags=re.M | re.A)
    collapsed = re.findall(r'^.+:(?P<offset>(?:[0-9A-F]{8}|[0-9A-F]{16})) +; +\[\d+ BYTES: COLLAPSED FUNCTION (?P<label>[\w()]+)\. PRESS CTRL-NUMPAD\+ TO EXPAND\].*$', lst_data, flags=re.M | re.A)

    labels_raw = set(public) | set(proc_near) | set(collapsed)

    entry_point_labels = ['DllEntryPoint', 'EntryPoint', 'start', 'WinMain', 'StartAddress']

    labels = list()
    for address, label in labels_raw:
        if re.match('sub_[0-9A-F]{6,9}', label) or label in entry_point_labels:
            continue
        stripped = address.lstrip('0')
        hex_int = int(stripped, 16)
        label_entry = {'module': module_name,
                       'address': hex_int - imagebase,
                       'manual': False,
                       'text': re.sub(r'\W', '_', label, flags=re.A)}
        labels.append(label_entry)

    if args.main:
        stripped = args.main.replace('0x', '')
        hex_int = int(stripped, 16)
        label_entry = {'module': module_name,
                       'address': hex_int - imagebase,
                       'manual': False,
                       'text': 'main'}
        labels.append(label_entry)

    _export_db(labels, input_path.stem, six_four, args.pretty, module_name)


def ghidra2x64dbg():
    """Extract labels from Ghidra CSV and export to x64dbg database.

    This command extracts all the labels found in the CSV file that is given as
    the single argument. An x64dbg database is created in the current directory
    based on the extracted labels. The imagebase value must be supplied.

    Example:
        $ ghidra2x64dbg -i 400000 sample.csv
    """
    parser = argparse.ArgumentParser(description='Extract labels from Ghidra CSV and export to x64dbg database.')
    parser.add_argument('csv', metavar='CSV', help='Filename or path of target CSV file.')
    parser.add_argument('-i', '--imagebase', help='Specify the imagebase value.', required=True)
    parser.add_argument('-p', '--pretty', action='store_true', help='Pretty print the database JSON.')
    parser.add_argument('-6', '--x64bit', action='store_true', help='Sample is 64bit.')
    parser.add_argument('-d', '--dll', action='store_true', help='File is a DLL.')
    parser.add_argument('-m', '--module', help='Specify the module name.')
    parser.add_argument('-r', '--main', help='Add main from radare2.')
    args = parser.parse_args()

    input_path = _open_input(args.csv)

    if args.module:
        module_name = args.module
    else:
        if args.dll:
            module_name = '{}.dll'.format(input_path.stem)
        else:
            module_name = '{}.exe'.format(input_path.stem)

    six_four = args.x64bit

    labels = list()
    with open(input_path) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if re.match(r'External\[(?:[0-9a-f]{8}|[0-9a-f]{16})\]', row['Location']):
                continue
            if row['Name'] == 'entry' or re.match(r'(?:thunk_)?FUN_[0-9a-f]{8}', row['Name']) or re.match(r'Ordinal_\d+', row['Name']):
                continue
            stripped = row['Location'].lstrip('0')
            hex_int = int(stripped, 16)
            label = re.sub(r'\W', '_', row['Name'], flags=re.A)
            label_entry = {'module': module_name,
                           'address': hex_int - int(args.imagebase, 16),
                           'manual': False,
                           'text': label}
            labels.append(label_entry)

    if args.main:
        stripped = args.main.replace('0x', '')
        hex_int = int(stripped, 16)
        label_entry = {'module': module_name,
                       'address': hex_int - int(args.imagebase, 16),
                       'manual': False,
                       'text': 'main'}
        labels.append(label_entry)

    _export_db(labels, input_path.stem, six_four, args.pretty, module_name)
