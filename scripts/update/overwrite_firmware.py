#!/usr/bin/env python3

import frida
import sys
import time
import binascii

class FirmwareLoader:
    """
    Overwrite a complete firmware during the update.

    TODO
    currently you also need to

        * continuously overwrite the ftab.bin file on the iPhone (15 seconds between unpacking and personalization)
        * wait until fud spawns and overwrite the personalization (again ~15 seconds until it requests sth from the TSS)

    iPhone:/private/var/MobileAsset/AssetsV2/com_apple_MobileAsset_MobileAccessoryUpdate_DurianFirmware/eba889b5f77e7aa5fb27e24adcf44b20a62c6dc1.asset/AssetData/DurianFirmware.acsw root#
        while true; do cp /var/root/ftab_rose_airtag_old.bin ftab.bin; sleep 1; done

    """

    def __init__(self):
        """
        Script configuration options.
        """

        print("\n\n\n!!!!!! HOOKING fud AND OVERWRITING ftab.bin MUST BE STARTED BEFORE THIS SCRIPT!\n\n\n")

        #self.firmware_dir = '../extracted_firmware_update/DurianFirmware_downgrade.acsw/'  # local directory (not on iPhone)
        self.firmware_dir = '../extracted_firmware_update/DurianFirmware_1A276d.acsw/'  # local directory (not on iPhone)
        self.firmware_intercept_prefix = "durian_fw_"  # TODO not implemented

        # only add the parts of the firmware that you want to be replaced
        self.replace_firmware = {
            1: "bldr.bin",  # boot loader
            2: "blsg.bin",  # boot loader signature
            3: "sftd.bin",  # soft device
            4: "sdsg.bin",  # soft device signature
            5: "blap.bin",  # bluetooth app
            6: "basg.bin",  # bluetooth app signature
            #7: "r1md.bin"  # r1md.bin is TSS signed ftab.bin, signature must match current nonce returned via GATT
        }

        self.overwrite_r1_signature = True
        # TODO sha384 sum currently hardcoded in the fud.js


        # Start Frida
        self.device = frida.get_usb_device()

        # Attach to searchpartyd to fake old versions in the SPBeacon
        frida_session_searchpartyd = self.device.attach("searchpartyd")
        self.searchpartyd_script = frida_session_searchpartyd.create_script(open("hook_durian_update_searchpartyd.js", "r").read())
        self.searchpartyd_script.load()
        print("  * Attached to searchpartyd.")

        # Attach to locationd with callback to replace the firmware.
        frida_session_locationd = self.device.attach("locationd")
        self.locationd_script = frida_session_locationd.create_script(open("hook_durian_update_locationd.js", "r").read())
        self.locationd_script.on("message", self.on_locationd_message)  # required for feedback
        self.locationd_script.load()
        print("  * Attached to locationd.")


        # And now hook into firmware loading :)
        self.load_firmware()

        # Don't quit the script...
        self.fud_attached = False
        while True:

            # the fud is only started on demand, hook it as soon as it becomes alive
            if self.overwrite_r1_signature and not self.fud_attached:
                try:
                    #print(" * Waiting for FUD...")
                    frida_session_fud = self.device.attach("fud")
                    fud_script = frida_session_fud.create_script(open("hook_durian_update_fud.js", "r").read())
                    fud_script.load()
                    print(" * Attached to FUD, update starting soon!")
                    self.fud_attached = True
                except:
                    pass
            else:
                time.sleep(120)  # just sleep, otherwise we attach multiple times to the fud
                self.fud_attached = False

    def on_locationd_message(self, message, data):
        """
        Handle locationd script feedback.
        """

        return

        # TODO
        print(message)

        payload = message['payload']
        message_type = payload['msgType']

        # Firmware interception
        if message_type == 'asset':
            asset_type = payload['assetType']
            print("  * Intercepted Durian firmware asset type " + asset_type)
            f = open(self.firmware_intercept_prefix + asset_type + ".bin", "wb")
            f.write(data)
            f.close()
            return

    def file_to_hex(self, filename):
        """
        Helper function to parse files as hex string for JSON serialization.
        :return:
        """

        return binascii.hexlify(open(filename, 'rb').read()).decode('ascii')

    def load_firmware(self):
        """
        Run all steps to trigger loading firmware and then also replace it.

        :return:
        """

        print("  * Sending custom firmware to the Frida script.")
        print(self.replace_firmware)
        for index in self.replace_firmware:
            asset = self.replace_firmware[index]
            firmware_file = self.firmware_dir + asset
            self.locationd_script.exports.setfirmwareasset(index, self.file_to_hex(firmware_file))



# run everything...
FirmwareLoader()