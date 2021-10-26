#!/usr/bin/env python3
# Split Durian firmware blob, similar to this one:
# https://gist.github.com/woachk/6092f9ae950455dcdf8428c3ce2d639e

# Most likely called "SuperBinary image" in Apple terminology,
# split by DurianUpdaterService.

import sys
import struct 
import os

def get_image_info(ftab, base_offset):
    # seek at the occurence which is the name of the image
    # first image should be rkos
    ftab.seek(base_offset)
    tag = ftab.read(4).decode()

    # get address of image
    ftab.seek(base_offset + 12)
    offset = struct.unpack('<i', ftab.read(4))[0]

    # get size of image
    ftab.seek(base_offset + 16)
    sz = struct.unpack('<i', ftab.read(4))[0]

    return tag, offset, sz


def split_firmware(ftab):
    default_offset = 0x10
    tag, offset, sz = get_image_info(ftab, 0x10)  # blap at offset 0x10
    offset_tag = offset

    print("tag : {}    offset : {}    size : {}".format(tag, hex(offset), hex(sz)))

    while default_offset < offset_tag:
        print("tag : {}    offset : {}    size : {}".format(tag, hex(offset), hex(sz)))

        ftab.seek(offset)
        img_data = ftab.read(sz)
        open(tag + '.bin', 'wb').write(img_data)

        default_offset += 20  # position of next magic
        tag, offset, sz = get_image_info(ftab, default_offset)
        
        if default_offset == offset_tag:
            return 0
    return 1


def main():
    if len(sys.argv) != 2:
        print("Usage: DurianFirmware_extract.py DurianFirmwareMobileAsset.bin")
        return 1

    firmware = sys.argv[1]

    ftab = open(firmware, 'rb')
    ftab.seek(0x10)

    magic = ftab.read(4)
    print(magic.decode())

    if magic.decode() != "blap":
        print("Image not starting with `blap`, different firmware format?")
        return 1

    split_firmware(ftab)

    ftab.close()

    return 0


if __name__ == '__main__':
	sys.exit(main())