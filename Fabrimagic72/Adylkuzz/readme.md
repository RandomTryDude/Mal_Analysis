# Base analysis 

## Checking the Exports using CFF_Explorer VIII

First things first, let's check the export table.

![Export Table](./Export_table.png)

The export table contains a few suspicious exports.  
I wouldn't trust a program that exports:
- `luaJIT_BC_hider`
- `luaJIT_BC_miner`

## Using DIE (Detect it easy) to check for possible known packing/protection

![Export Table](./DIE.png)

This confirm we wont be able to just read assembly , since it's packed only when ran will it be readable.



