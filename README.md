# lst2x64dbg
This script extracts all the labels found in the LST file that is given as
the script's single argument. An x64dbg database is created in the current
directory based on the extracted labels.

The LST file can be generated in IDA from the **File** menu: **Produce file -> Create LST file...**

## Example

    $ python3 lst2x64dbg.py sample.lst

## ToDo
* Convert to package with console script
