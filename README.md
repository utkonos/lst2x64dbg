# lst2x64dbg
This command extracts all the labels found in the LST file that is given as
the single argument. An x64dbg database is created in the current directory
based on the extracted labels.

The LST file can be generated in IDA from the **File** menu: **Produce file -> Create LST file...**

## Example

    $ lst2x64dbg sample.lst

# ghidra2x64dbg
This command extracts all the labels found in the CSV file that is given as
the single argument. An x64dbg database is created in the current directory
based on the extracted labels. The imagebase value must be supplied.

The CSV file can be generated in Ghidra from the **Window** menu by selecting **Symbol Table**

In the symbol table window that opens, sort the data by the **Location** column. Then select all
symbols that are *not* external locations. With the desired symbols selected, right click and select:
**Export -> Export to CSV...**

**NOTE: If you happen to select external locations, they will be ignored.**

![Symbol Table](/images/symbol_table.png)

Name this file `<module_name>.csv`

## Example

    $ ghidra2x64dbg -i 400000 sample.csv

The imagebase value can be found at the very top of the disassembly panel in the CodeBrowser window.
It's part of the DOS header.

![Image Base](/images/imagebase.png)

## Configuration for More Labels

Ghidra has one analysis option that is off by default that can provide more labels for code in a sample in certain situations. This option, `WindowsPE x86 Propagate External Parameters` is found in the Analysis Options window when a sample is first opened in the CodeBrowser tool.

![Analysis Options](/images/ghidra_more_labels.png)

# Support for radare2
Both commands now support inclusion of the location for main() as detected by
radare2. Just add `-r` or `-main` to either command like this:

    $ lst2x64dbg -m 0x0040a53a sample.lst

Just cut and paste the virtual address for main from Cutter's UI or from radare2 command line.

![Main](/images/radare2_main.png)
