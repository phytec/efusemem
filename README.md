# efusemem

Tool to read/write efuses through NVMEM on NXP based modules.
Currently supported SoC's:
  - i.MX6ULL

Product State
=============
Alpha  
implemented functions are not finally tested!

Dependencies
============

For building *efusemem* from source the following dependencies are needed:

-  `Meson Build <https://mesonbuild.com/>`

Building
========

Build *efusemem* using the `Meson Build system <https://mesonbuild.com>` 

   meson setup build  
   meson compile -C build

Running
=======
```
efusemem read/write/lock [fhkmryv] <options> <path_to_nvmem>

Read/Write options:  
  -k --hash     read/write HASH from commandline
  -f --file     write HASH from file
  -m --mac      read/write MAC address from commandline
  -r --revoke   revoke keys
Lock options:
  --secureboot	Enable Secureboot and lock HASH
  --sdp         lock serial download port
  --jtag        lock (disable) JTAG port
General options:
  -y --force    bypass user confirm. Say yes to all
  -h --help     print help info
  -v --version  print version of the program
path_to_nvmem
  for i.MX6UL: /sys/bus/nvmem/devices/imx-ocotp0/nvmem
```
