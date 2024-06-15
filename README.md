# AirTag Scripts & Resources


## FЯIDA Script Overview

![AirTag: Play custom sound, UWB, firmware version, downgrade](assets/airtag_frida.png)


### Prerequisites

The scripts require a jailbroken iPhone, paired with an AirTag, and a host system, running
[FЯIDA](https://frida.re).

AirTag support was introduced as of iOS 14.5. So far, we tested the scripts provided here on various
iOS versions (14.6, 14.7, 14.8) on [checkm8](https://checkra.in)-supported devices.
The scripts might run on Fugu14 as well, but we didn't test that yet.

### Run custom tasks, enumerate commands

Use [hook_durian.js](scripts/hook_durian.js) to
play custom sounds aka [AirTechno](https://www.youtube.com/watch?v=z1DJ7z_LaUM),
and also run and decode all other L2CAP commands. Commands are described by opcodes,
and opcodes can be enumerated to list their meanings.


It's possible to run raw commands. However, some commands require a mutex or special
state. Thus, ideally, create a task, which will take care of creating a command,
including mutex handling. Objective-C allows to extract a full command list, included
in the comments of `hook_durian.js`, so that you don't need to enumerate them.
For example, `unpairTask`, `stopSoundTask`, etc.

```JavaScript
// run a predefined task
d.performTaskByName('stopSoundTask');

// run a task with custom opcode 0x01 and payload 0x02030405
d.performTaskWithCommand([1, 2, 3, 4, 5]);
```

Some tasks require parameters. These aren't fully reverse engineered yet.
Depending on the command, you might need to add a custom function.
For example, you can play custom sounds:

```JavaScript
// play sound sequence id 1, twice, with 0 offset, and 0 pause
d.playSoundSequence[1, 2, 0, 0];
```

To set the `DurianService` etc. to call task, manually play a sound 
via the Find My app on the AirTag once.


### Hook the firmware update process for downgrades

A detailed description of the downgrade process including script
explanations is available on [YouTube](https://www.youtube.com/watch?v=C4JyI_WUNJ8).

#### 1. Download the firmware version you want

[The Apple Wiki](https://www.theapplewiki.com/wiki/OTA_Updates/AirTag) hosts an
up-to-date list of all firmware updates released for the AirTag. Note that the very first
stock version (1.0.225) was never released as OTA, so you cannot use the method here to
downgrade to the very first version that did not have any anti-stalking protections.

#### 2. Extract the U1 firmware (aka Rose) from the super binary (optional)

If you want to downgrade the U1 firmware as well, you can extract it using
[DurianFirmware_extract.py](scripts/DurianFirmware_extract.py).

```bash
mkdir airtag_firmware_1A276d
cd airtag_firmware_1A276d
wget https://updates.cdn-apple.com/2021/patches/071-45785/4132D4FE-1C5A-498E-8A6D-678A026679AF/com_apple_MobileAsset_MobileAccessoryUpdate_DurianFirmware/ae34f4b8aec8a4d4562227109be101728b7bef20.zip
python3 DurianFirmware_extract.py AssetData/DurianFirmware.acsw/DurianFirmwareMobileAsset.bin
```

This will extract the following files, with `ftab` being the U1 firmware.

```buildoutcfg
tag : blap    offset : 0x9c       size : 0x38340
tag : sftd    offset : 0x383dc    size : 0x1b400
tag : bldr    offset : 0x537dc    size : 0x5f9c
tag : basg    offset : 0x59778    size : 0x47
tag : sdsg    offset : 0x597c0    size : 0x48
tag : blsg    offset : 0x59808    size : 0x47
tag : ftab    offset : 0x59850    size : 0x924c5
```


#### 3. Overwrite the U1 firmware while the downgrade is running (optional)

Replace the `sha384sum` of `rkos` and `dsp1` in the [hook_durian_update_fud.js](scripts/update/hook_durian_update_fud.js) script
with the matching ones. For this, you also have to split the `ftab` using the external [ftab_split.py](https://gist.github.com/matteyeux/c1018765a51bcac838e26f8e49c6e9ce) script.

```bash
ftab_split.py ftab.bin 
sha384sum rkos 
    1fcb05b377eb405eeffc5ad60efce6aeed3b83d834e0403bd88a142d84c6082ea6c649ebf14ae05b1a87d159e9dc167c  rkos
sha384sum sbd1 
    928a226b85b52c75f07fb3cd89f1c38a783bb9834de647407b935a952359d36b243a58fa43a172d1e39c3d432d1a3030  sbd1
```

Now we can use the TOCTOU to overwrite the firmware. Double-check which firmware is being used for the update,
the folder might differ. The following is running on the iPhone:

```
iPhone:/private/var/MobileAsset/AssetsV2/com_apple_MobileAsset_MobileAccessoryUpdate_DurianFirmware/[your_version].asset/AssetData/DurianFirmware.acsw root#
   while true; do cp /var/root/ftab_rose_airtag_old.bin ftab.bin; sleep 1; done
```

#### 4. Run the downgrade

If you're not downgrading Rose and only the nRF parts, you might need to adapt [overwrite_firmware.py](scripts/update/overwrite_firmware.py).
Otherwise, simply run:

```bash
python3 overwrite_firmware.py
```

Now, remove your AirTag from your account and pair it again. The update should start within 5 minutes.
If this wasn't the case, check your `idevicesyslog`. Possible reasons:

* Concurrent interaction with the AirTag that delayed the update process by 2h 30min. Just pair again.
* The current AirTag firmware version has a `deploymentLimit`. Can probably fixed by overwriting the `xml` file
  in the same folder as the asset location on the iPhone.


### L2CAP command opcodes

The full list of L2CAP opcodes, since they might also be useful for reverse engineering and building
clients independent of iOS. Note that Durian opcodes are for AirTags, and Hawkeye opcodes are likely
for third-party Find My devices.


```buildoutcfg
Durian opcode list: 
[d] 0: Acknowledge
[d] 1: Rose Init
[d] 2: Rose Ready
[d] 3: Rose Start Ranging
[d] 4: Rose Ranging Complete
[d] 6: Rose Stop
[d] 7: Get Firmware Version
[d] 8: Stop Sound
[d] 10: Leashing
[d] 11: Set Max Connections
[d] 12: Get Multi Status
[d] 13: Set Obfuscated Identifier
[d] 14: Set Mutex
[d] 15: Set Near Owner Timeout
[d] 18: Get Firmware Version (Deprecated)
[d] 19: Unpair
[d] 21: Rose Set Paramaters
[d] 22: Rose Stop Ranging
[d] 24: Get User Stats
[d] 32: Abort FWDL
[d] 34: Rose Error
[d] 36: Rose P2P Timestamp
[d] 37: Rose Debug P2P Timestamp
[d] 38: Set Tag Type
[d] 39: Get Battery Status
[d] 40: Play Sound Sequence
[d] 42: Set Wild Mode Configuration
[d] 43: Roll Wild Key
[d] 45: Set Absolute Wild Mode Configuration
[d] 174: Fetch Current Key Index
[d] 175: Play Unauthorized Sound
[d] 177: Set Key Rotation Timeout
[d] 180: Dump Logs
[d] 181: Check Crashes
[d] 185: Induce Crash
[d] 195: Enable/Disable UT PlaySound Rate Limit
[d] 197: Set Central Reference Time
[d] 199: Set Accelerometeter Slope Mode Configuration
[d] 200: Set Accelerometer Orientation Mode Configuration
[d] 201: Get Accelerometer Slope Mode Configuration
[d] 202: Get Accelerometer Orientation Mode Configuration
[d] 203: Get Accelerometer Mode
[d] 209: Fetch ProductData AIS
[d] 210: Fetch ManufacturerName AIS
[d] 211: Fetch ModelName AIS
[d] 212: Fetch ModelColorCode AIS
[d] 213: Fetch AccessoryCategory AIS
[d] 214: Fetch AccessoryCapabilities AIS
[d] 215: Fetch FirmwareVersion AIS
[d] 216: Fetch FindMyVersion AIS
[d] 217: Fetch BatteryTyp AIS
[d] 218: Fetch BatteryLevel AIS
[d] 219: Send UARP message to accessory
[d] 220: Stop Unauthorized Sound

Hawkeye opcode list: 
[h] 512: Sound Start
[h] 513: Sound Stop
[h] 514: Persistent Connection Status
[h] 515: Nearby Timeout
[h] 516: Unpair
[h] 517: Configure Separated State
[h] 518: Latch Separated Key
[h] 519: Set Max Connections
[h] 520: Set UTC
[h] 521: Get Multi Status
[h] 523: Command Response
[h] 524: Multi Status Response
[h] 525: Sound Complete
[h] 768: Non-Owner Sound Start
[h] 769: Non-Owner Sound Stop
[h] 770: Non-Owner Command Response
[h] 771: Non-Owner Sound Complete
[h] 1024: Get Current Primary Key
[h] 1025: Get iCloud Identifier
[h] 1026: Get Current Primary Key Response
[h] 1027: Get iCloud Identifier Response
[h] 1028: Get Serial Number
[h] 1029: Get Serial Number Response
[h] 1280: Key Rotation
[h] 1281: Retrieve Logs
[h] 1282: Log Response
[h] 1283: Debug Command Response
[h] 1284: Reset
[h] 1285: UT Motion Config
```


