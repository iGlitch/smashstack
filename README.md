# SmashStack for Wii/vWii

Smash Stack is an exploit from Comex that uses a flaw in the custom stages in Super Smash Bros. Brawl to load unauthorized code on the Wii and vWii. It works for all System Menu versions and most regions.

This is the source code Pune used to create his version of the smashstack exploit.
All the uploaded bins have a specific region they belong to, read the file name.

All code involved is licensed under GPLv2.  It comes with no warranty, only the guarentee that it may or may not work.  the product that this code produces also comes with no warranty.  it has been tested only on 1 wii - Pune's.  Any unusual or unexpected occurence (such as bricked consoles) are none other than your own responsibility and fault.  I do not take any responsibility in your usage.

It comes from many different people, and parts have been ported & rewritten multiple times. In its current state, there is a dependancy for the Qt 4.7.x LGPL SDK.

Requires a loader.bin from the twilight hack. You must provide that yourself.

# Building
Pune used devkitPPC r17 to build the elf loader.  Using a different compiler will result in a different program which may be different in size and probably compresses differently than the version Pune used.  The entrypoint in loader.lds must be changed depending on which version of the exploit you are making

Using the Qt 4.7.x SDK, build the code in the smashStageCrypter directory.  **there is an #ifndef in main.cpp to change depending on which version you are making.  this program reads "../loader/loader.bin", then builds the sploit out of it and writes this to argv[ 1 ].**


# Credits
* team twiizers - elf loader
* svpe & comex - pointing out the buffer overflow in the game
* comex - original python SSBB checksum
* Xanares - stage format documentation, encryption & checksum code contained in this package
* not.nmn - c# lz77 compression code which was used as a base
* giantpune - debugging, poking, building, disassembling, testing, putting all the pieces together, creating a working exploit

# and huge thanks to:
nuke, link, dcx2, brkirch, Y.S, Frank Willie, et al - usb gecko, geckoOS, vdappc, geckoDotNET
megazig, dcx2 - lots of useful knowledge concerning ASM, registers, PPC behavior, and other similar low-level stuff
