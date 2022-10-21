/*
Hooking into locationd, which handles most AirTag interaction.

Attach as follows:

   frida -U locationd --no-pause -l hook_durian_update_locationd.js

To set the DurianService etc. to call task, play a sound on the AirTag once.


*/


class Durian {

    constructor() {

        /*** INITIALIZE SCRIPT ***/
        this.ios_version = "arm64_14.7";  // TODO adjust iOS version here!

        // intercepted from a packet log, starts with L2CAP 91 15 07
        this.durian_version_bytes = [0x13, 0x10, 0x0e, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0f, 0x00]; //1.0.225
        this.durian_version_string = '1.0.225';  // matching string
        //this.durian_version_bytes = [0x13, 0x40, 0x11, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 0f 00]; //1.0.276
        //                             ^-0x114 = 276
        //this.durian_version_string = '1.0.276';
        this.durian_serial = 'TROLOLOLOLOL';


        this.log_verbose = false;  // switch logging verbosity

        // global vars for the current device
        this.durian_service;
        this.durian_client;
        this.durian_device;

        // global vars for the injected firmware
        this.replace_firmware = {};

    }



    /*
    Script preparation, needs to be called in standalone usage.
    Separated from constructor for external script usage.
    */
    prepare() {

        var self = this;

        // some basic addresses
        self._locationd_base = Module.getBaseAddress('locationd');
        self._CoreBluetooth_base = Module.getBaseAddress('CoreBluetooth');
        self._objc_msgSend_addr = Module.getExportByName('libobjc.A.dylib', 'objc_msgSend');
        self._objc_msgSend = new NativeFunction(self._objc_msgSend_addr, 'pointer', ['pointer', 'pointer']);

        // Set the correct symbols
        self.setSymbols(self.ios_version);

        // hook sent/received bytes and show them
        self.showBytes();  // this one changes the version bytes in L2CAP
        self.debugStuff();

        // hook into exiting global vars
        self.hookServiceClientDevice();

        // also overwrite the version in a few more places
        self.overwriteSPBeacons();
        self.interceptFirmwareUpdate();

        // modify the maximul packet size
        self.setPacketSize();

        // print opcode list
        //self.printOpcodes();
    }

    // Backtrace helper function
    print_backtrace(ctx) {
        console.log('Backtrace:\n' +
        Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).join('\n') + '\n');
    }

    // Helper function to print hex
    print_hex(byte_array) {
        var bytes_string = "";
        for (var i = 0; i < byte_array.length; i+=1) {
            bytes_string += ("00" + byte_array[i].toString(16)).substr(-2);
        }
        console.log('\t' + bytes_string);
    }



    /*
     Show raw bytes as sent/received within locationd. Already misses the L2CAP metadata.
    */
    showBytes() {
        var self = this;

        var {CLDurianDeviceManager} = ObjC.classes;

        Interceptor.attach(CLDurianDeviceManager['- centralManager:didSendBytes:toPeripheral:withError:'].implementation, {
            onEnter: function(args) {
                if (self.log_verbose) {
                    console.log("  * Sent bytes!");
                }

                // precise bytes are logged via tasks, not needed here

            }
        });

        Interceptor.attach(CLDurianDeviceManager['- centralManager:didReceiveData:fromPeripheral:'].implementation, {
            onEnter: function(args) {
                //self.print_backtrace(this.ctx);

                var len = args[3].add(8).readU32();
                var op = args[3].add(0x10).readU8();
                console.log("  * Received " + len + " bytes! Opcode " + op + " (" + self.getDurianOpcodeDescription(op) + ")");

                if (op == 7 && len > 2) {  // overwrite replies with a version payload
                    console.log(" ! OVERWRITING FIRMWARE VERSION REPLY");
                    args[3].add(0x11).writeByteArray(self.durian_version_bytes);
                }

                // log acknowledged opcode
                if (op == 0) {
                    op = args[3].add(0x11).readU8();
                    console.log("              > ACKed Opcode " + op + " (" + self.getDurianOpcodeDescription(op) + ")");
                }
                else if (op == 255) {
                    op = args[3].add(0x11).readU8();
                    console.log("              > NACKed Opcode " + op + " (" + self.getDurianOpcodeDescription(op) + ")");
                }

                if (self.log_verbose) {
                    console.log(args[3].add(0x10).readByteArray(len));
                }

            }
        });

    }

    /*
    Called via -[CLDurianTask opcodeDescription].
    Opcode as integer.
    */
    getDurianOpcodeDescription(opcode) {
        var self = this;

        // "Unknown" opcodes we actually know
        if (opcode == 255) {
            return "NACK";
        }
        else if (opcode == 9) {
            return "Playing Sound"
        }

        var getOpcodeString = new NativeFunction(self._DurianOpcodeDescription.sign(), 'pointer', ['int64']);
        var desc = new ObjC.Object(getOpcodeString(opcode));
        return desc.toString();
    }

    getHawkeyeOpcodeDescription(opcode) {
        var self = this;
        var getOpcodeString = new NativeFunction(self._HawkeyeOpcodeDescription.sign(), 'pointer', ['int64']);
        var desc = new ObjC.Object(getOpcodeString(opcode));
        return desc.toString();
    }

    /*
    Prints a list of opcodes.
    */
    printOpcodes() {

        var self = this;

        console.log("Durian opcode list: ")
        for (let op = 0; op <= 255; op++) {
            var desc = self.getDurianOpcodeDescription(op);
            if ("Unknown".localeCompare(desc) != 0) {
                console.log("[d] " + op + ": " + desc);
            }
        }

        console.log("Hawkeye opcode list: ")
        for (let op = 512; op <= 1300; op++) { //not iterating the full 2 bytes here
            var desc = self.getHawkeyeOpcodeDescription(op);
            if ("Unknown".localeCompare(desc) != 0) {
                console.log("[h] " + op + ": " + desc);
            }
        }
    }

    debugStuff() {

        var self = this;

        // -[CLDurianTask initWithCommand:desiredLatency:expectsResponse:completeOnPreemption:requiresMutex:]
        var {CLDurianTask} = ObjC.classes;
        Interceptor.attach(CLDurianTask['- initWithCommand:desiredLatency:expectsResponse:completeOnPreemption:requiresMutex:'].implementation, {
            onEnter: function(args) {
                if (self.log_verbose) {
                    console.log("  * CLDurianTask init");
                }
                //console.log(args[0].readByteArray(0x10)); self
                var task = new ObjC.Object(args[0]);  // CLDurianTask
                //console.log("    v " + task.toString()); // not helpful, uninitialized task is always an Acknowledgment task
                //console.log(args[1].readByteArray(0x10)); SEL: 'initWithCommand:' ...

                if (args[2] != 0) {  // opcode can be 0, resulting in an access violation
                    var opcode = args[2].add(8).readInt();  // direct access to the opcode via the CLDurianCommand w/o ObjC API
                    console.log("     > opcode:               " + opcode + " (" + self.getDurianOpcodeDescription(opcode) + ")");  // command is 0: super + 8: opcode + 0x10: payload
                    if (self.log_verbose) {
                        console.log("     > desiredLatency:       " + args[3]);  // latency can also be negative
                        console.log("     > expectsResponse:      " + args[4]);
                        console.log("     > completeOnPreemption: " + args[5]);
                        console.log("     > requiresMutex:        " + args[6]);
                        // logging payload but length is defined by opcode so we don't know it here
                        //console.log(args[2].add(0x10).readByteArray(0x10));
                    }

                    // The task is already initiated with a pre-filled DurianCommand. This has an uint8 opcode
                    // as well as an NSData payload. The CLDurianCommand.-bytes returns both of these concatenated
                    // to NSData.
                    var command = new ObjC.Object(args[2]);  // CLDurianCommand
                    var {NSString} = ObjC.classes;
                    var bytes = command['- bytes'].implementation(command, NSString['stringWithString:']('-bytes'));
                    var b_len = bytes.add(8).readInt();
                    var raw_bytes = bytes.add(0x10).readByteArray(b_len);

                    if (self.log_verbose) {
                        console.log(raw_bytes);
                    }

                    //self.print_backtrace(this.ctx);
                }

            }
        });

        // -[CLDurianService playSoundSequence:onTag:forClient:](CLDurianService *self, SEL a2, id soundsequence, id ontag, id forclient)
        var {CLDurianService} = ObjC.classes;
        Interceptor.attach(CLDurianService['- playSoundSequence:onTag:forClient:'].implementation, {
            onEnter: function(args) {
                console.log("  * CLDurianService playSoundSequence");
                //self.print_backtrace(this.ctx);
            }
        });

        // +[CLDurianService performSyncOnSilo:invoker:]
        Interceptor.attach(CLDurianService.performSyncOnSilo_invoker_.implementation, {
            onEnter: function(args) {
                console.log("  * CLDurianService performSyncOnSilo");
                //self.print_backtrace(this.ctx);
            }
        });

        var {CLDurianDevice} = ObjC.classes;

        // -[CLDurianDevice executeTask:](CLDurianDevice *self, SEL a2, id task)
        Interceptor.attach(CLDurianDevice['- executeTask:'].implementation, {
            onEnter: function(args) {
                console.log("  * [" + Date() + "] CLDurianDevice executeTask");
                //self.print_backtrace(this.ctx);

            }
        });

    }


    
    /*
    Further hook needed to fake the version in the search party beacon.

    Every time a SPBeacon is created, all its setters are called:

        -[SPBeacon setIdentifier:0x149d8fb00]
        -[SPBeacon setModel:0x1fe7b4080]
        -[SPBeacon setShares:0x1fea03120]
        -[SPBeacon setSystemVersion:0xb19247ee008b482b]
        -[SPBeacon setVendorId:0x4c]
        -[SPBeacon setProductId:0x5500]
        - ... (and more)

    Since this is no plain copy but calls all these functions, we can hook the functions
    to set our own version.
    */
    overwriteSPBeacons() {

        // SearchParty Beacon from searchpartyd, defined in SPOwner
        var {SPBeacon} = ObjC.classes;
        var {NSString} = ObjC.classes;
        var self = this;




        // all setters are called upon SPBeacon creation, overwrite these
        Interceptor.attach(SPBeacon['- setSystemVersion:'].implementation, {
            onEnter: function(args) {
                var version = new ObjC.Object(args[2]);
                args[2] = NSString['stringWithString:'](self.durian_version_string);
                version = new ObjC.Object(args[2]);
                if (self.log_verbose) {
                    console.log("   > observed version: " + version);
                    console.log("   > new version:      " + version);
                }
            }
        });

        Interceptor.attach(SPBeacon['- setSerialNumber:'].implementation, {
            onEnter: function(args) {
                var serial = new ObjC.Object(args[2]);
                args[2] = NSString['stringWithString:'](self.durian_serial);
                serial = new ObjC.Object(args[2]);
                if (self.log_verbose) {
                    console.log("   > observed serial: " + serial);
                    console.log("   > new serial:      " + serial);
                }
            }
        });
    }


    

    /*
    When fud and DurianUpdaterService are done, they just call locationd with the according asset
    URL.
    */
    interceptFirmwareUpdate() {
        var self = this;

        // -[CLDurianService updateFirmwareForDevice:withAssetURL:forClient:]
        var {CLDurianService} = ObjC.classes;
        Interceptor.attach(CLDurianService['- updateFirmwareForDevice:withAssetURL:forClient:'].implementation, {
            onEnter: function(args) {
                console.log(' ! ENTERED FIRMWARE UPDATE');
                // withAssetURL as ObjC prints: file:///private/var/MobileAsset/AssetsV2/com_apple_MobileAsset_MobileAccessoryUpdate_DurianFirmware/eba889b5f77e7aa5fb27e24adcf44b20a62c6dc1.asset/AssetData/DurianFirmware.acsw/
                console.log(new ObjC.Object(args[3]));
            }
        });

        // all sub binaries (blap.bin etc.) are sent separately by the asset packetizer
        var {CLDurianFirmwareAssetPacketizer} = ObjC.classes;
        Interceptor.attach(CLDurianFirmwareAssetPacketizer['- initWithAssetType:assetData:maxPacketSize:'].implementation, {
            onEnter: function(args) {
                var assetType = parseInt(args[2]);
                console.log(' * Creating new asset data packet with type ' + assetType);
                var assetData = new ObjC.Object(args[3]);
                console.log(assetData);  //NSData

                //TODO
                // send to Python script for further processing
                //var blob = assetData.bytes().readByteArray(assetData.length());
                //send({msgType: "asset", assetType: assetType}, blob);

                // also overwrite if asset is set
                if (self.replace_firmware[assetType]) {
                    this.context.x3 = self.replace_firmware[assetType];
                    console.log(' ! FOUND BLOB FOR ' + assetType + ', REPLACED FIRMWARE!');

                }
            }
        });

    }

    /*
    Get more granularity into the update. (sloooow!)
    */
    setPacketSize() {
        var self = this;

        // [CLDurianFirmwareAssetPacketizer initWithAssetType:assetData:maxPacketSize:] calls the function
        // -[CLDurianFirmwareAssetPacketizer setMaxPayloadSize:] and sets it to maxPacketSize - 6 (type + offset)
        var {CLDurianFirmwareAssetPacketizer} = ObjC.classes;
        Interceptor.attach(CLDurianFirmwareAssetPacketizer['- setMaxPayloadSize:'].implementation, {
            onEnter: function(args) {
                var packetizer = new ObjC.Object(args[0]);  // CLDurianFirmwareAssetPacketizer
                var assetType = packetizer.assetType();
                var limit = 4;  // new payload size limit

                console.log(' * Original max payload size for asset type ' + assetType + ': ' + args[2]);

                // check for asset type as well, signatures should not be fragmented, only
                // the main binaries
                /*
                //if (assetType == 1 || assetType == 3 || assetType == 5) {
                if (assetType == 5) {  // only blap.bin
                //if (assetType == 1) {  // only bldr.bin

                    this.context.x2 = limit;
                    console.log(' ! Packet size set to ' + limit);
                }
                */
            }
        });
    }


    /*
    Call a firmware update. Requires that everything is already unpacked.
    Probably only useful for extensive firmware update testing.
    */
    triggerFirmwareUpdate() {
        var self = this;
        var {CLDurianService} = ObjC.classes;
        var {NSURL} = ObjC.classes;

        var url = NSURL['fileURLWithPath:']('/private/var/MobileAsset/AssetsV2/com_apple_MobileAsset_MobileAccessoryUpdate_DurianFirmware/eba889b5f77e7aa5fb27e24adcf44b20a62c6dc1.asset/AssetData/DurianFirmware.acsw/');
        console.log(url);
        // TODO causes an abort, doesn't work :(
        CLDurianService['- updateFirmwareForDevice:withAssetURL:forClient:'](self.durian_device, url, self.durian_client);
    }

    /*
    We reuse these pointers so that we don't need to create a service.
    */
    hookServiceClientDevice() {
        var self = this;

        var {CLDurianService} = ObjC.classes;
        Interceptor.attach(CLDurianService['- performTask:forClient:onDevice:'].implementation, {
            onEnter: function(args) {
                if (! self.durian_device) {
                    console.log("  * Setting DurianService, DurianClient, DurianDevice...");
                    self.durian_service = args[0];
                    self.durian_client = args[3];
                    self.durian_device = args[4];
                }
                else if (parseInt(self.durian_service) != parseInt(args[0]) || parseInt(self.durian_client) != parseInt(args[3]) || parseInt(self.durian_device) != parseInt(args[4])) {
                    console.log("  * Updating DurianService, DurianClient, DurianDevice, values changed!");
                    self.durian_service = args[0];
                    self.durian_client = args[3];
                    self.durian_device = args[4];
                }
                else {
                    console.log("  - Performing a task, DurianService unchanged...");
                }
            }
        });
    }



    /*
    NSData helper function required to allocate parameters in CLDurianCommands.
    Takes input array in the form [1, 2, 3, 4, ...] as passed by JavaScript.
    */
    allocNSData(bytes) {
        // alloc memory for raw bytes
        var params_raw = Memory.alloc(bytes.length);
        params_raw.writeByteArray(bytes);

        // NSData['- initWithBytes:length:']
        var {NSData} = ObjC.classes;
        return NSData.alloc().initWithBytes_length_(params_raw, bytes.length);
    }


    /*
    Creates a task (CLDurianTask) only by its name. Works for tasks with only 2 arguments (self + name).
    Tested with:
        * getSerialNumberTask
        * dumpRoseLogsTask (does not work bc of state)
    */
    createTaskByName(name) {
        var {CLDurianTask} = ObjC.classes;
        var {NSString} = ObjC.classes;
        var taskByName = CLDurianTask[name];
        return taskByName.implementation(CLDurianTask, NSString['stringWithString:'](name)); //TODO sometimes hangs? ObjC might still be wrong here!
    }

    createTaskByNameWithArg(name, arg) {
        var {CLDurianTask} = ObjC.classes;
        var {NSString} = ObjC.classes;
        var taskByName = CLDurianTask[name];
        return taskByName.implementation(CLDurianTask, NSString['stringWithString:'](name), arg); //TODO could hang on wrong arg types but it's undefined
    }

    /*
    Runs a task.
    */
    runTask(task) {
        var self = this;

        if (self.durian_service) {

            console.log("  * Scheduling task...");

            // -[CLDurianService performTask:forClient:onDevice:]
            var {CLDurianService} = ObjC.classes;
            var _CLDurianService_performTask_forClient_onDevice = CLDurianService['- performTask:forClient:onDevice:'].implementation;

            _CLDurianService_performTask_forClient_onDevice(
                self.durian_service,                        // CLDurianService *self
                Memory.allocUtf8String("performTask:forClient:onDevice:"),          // SEL
                task,
                self.durian_client,
                self.durian_device,
                );

            console.log("  * Scheduled task.");

        } else {
            console.log('  ! DurianService not set! Try playing a sound on your AirTag.');
        }

    }

    /*
    Call task by its name, i.e., 'dumpRoseLogsTask'.
    Does not pass any parameters!
    */
    performTaskByName(name) {
        var self = this;
        var task = self.createTaskByName(name);
        self.runTask(task);
    }

    /*
    Same but with one argument (for those that end with :).
    Argument types are not defined, though!
    */
    performTaskByNameWithArg(name, arg) {
        var self = this;
        var task = self.createTaskByNameWithArg(name, arg);
        self.runTask(task);
    }

    /*
    Create a custom task.
    Requires creating a CLDurianCommand with a custom data (byte array) first, and then using this
    to initialize a new CLDurianTask.

    The -[CLDurianCommand initWithData:] will split NSData into opcode (first byte) and payload.
    */
    performTaskWithCommand(data) {
        var self = this;

        // create custom command
        var {CLDurianCommand} = ObjC.classes;
        var command = CLDurianCommand.alloc().initWithData_(self.allocNSData(data));

        // create and run task
        // TODO if needed, adjust latency, response, complete, mutex params here... depends a lot on the use case
        var {CLDurianTask} = ObjC.classes;
        var task = CLDurianTask.alloc().initWithCommand_desiredLatency_expectsResponse_completeOnPreemption_requiresMutex_(command, 1, 0, 0, 1);
        self.runTask(task);
    }


    /*
    Version-specific symbols, needs to be adjusted for every version.
    */
    setSymbols(ios_version) {

        console.log(" * Automatically detecting symbols...");
        var self = this;

        // at offset 28 in -[CLDurianTask opcodeDescription] there's a branch instruction to the function we need
        var {CLDurianTask} = ObjC.classes;
        var opcodeDescription = new NativePointer(CLDurianTask['- opcodeDescription'].implementation);

         // check if we have PAC assembly for hacks below, starts with PACIBSP
        var is_pac = false;
        if ("pacibsp".localeCompare(Instruction.parse(opcodeDescription).mnemonic) == 0) {
            is_pac = true;
            console.log("  > Determining symbols with PAC enabled.");
        }

        if (! is_pac) {
            self._DurianOpcodeDescription = new NativePointer(Instruction.parse(opcodeDescription.add(28)).operands.pop().value);
        } else {
            self._DurianOpcodeDescription = new NativePointer(Instruction.parse(opcodeDescription.add(12*4)).operands.pop().value);
        }
        console.log("  > _DurianOpcodeDesription " + self._DurianOpcodeDescription);


        // at offset 24 in -[CLHawkeyeTask opcodeDescription] there's a branch instruction to the function we need
        var {CLHawkeyeTask} = ObjC.classes;
        var opcodeDescription = new NativePointer(CLHawkeyeTask['- opcodeDescription'].implementation);
        if (! is_pac) {
            self._HawkeyeOpcodeDescription = new NativePointer(Instruction.parse(opcodeDescription.add(24)).operands.pop().value);
        } else {
            self._HawkeyeOpcodeDescription = new NativePointer(Instruction.parse(opcodeDescription.add(11*4)).operands.pop().value);
        }

        console.log("  > _HawkeyeOpcodeDescription " + self._HawkeyeOpcodeDescription);


    }

    setFirmwareAsset(index, blob) {
        var self = this;
        index = parseInt(index);  // index is always integer

        if (! self.replace_firmware[index]) {
            // gnaaaaah types -.-
            var a = self.hex_to_array(blob);     // JSON to Array
            a = a.readByteArray(blob.length/2);  // Array to ByteArray (not sure what's the difference here)
            a = new Uint8Array(a);               // convert to JavaScript Array
            a = self.allocNSData(a);             // convert to NSData
            self.replace_firmware[index] = a;    // save to firmware blobs
            console.log(" * Added firmware blob for asset type " + index);

        }
    }

    // Conversion needed for the firmware
    hex_to_array(payload) {

        // create null pointer if needed
        if (payload.length == 0) {
            return new NativePointer(0x0);
        }

        const payload_array = [];
        var target_array = Memory.alloc(payload.length / 2);
        for (var i = 0; i < payload.length; i += 2) {
            payload_array.push(parseInt(payload.substring(i, i + 2), 16));
        }

        // Copy to buffer
        Memory.writeByteArray(target_array, payload_array);

        return target_array;
    }


    // Export class methods for Frida
    // Required to inject firmware via python from a local machine
    makeExports() {
        var self = this;
        return {
            setsymbols: (ios_version) => {return self.setSymbols(ios_version)},
            setfirmwareasset: (index, blob) => {return self.setFirmwareAsset(index, blob)},
            prepare: () => {return self.prepare()},
        }
    }

}

var d = new Durian();

// Prepare the target function
d.prepare(); //TODO call this when standalone

// Required to interact with Python ...
// Yep even the standalone fuzzer should use this because calling the fuzzer
// directly will timeout on large payloads
rpc.exports = d.makeExports();
rpc.exports.d = Durian;
