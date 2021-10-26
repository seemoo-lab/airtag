/*
Hooking into locationd, which handles most AirTag interaction.

Attach as follows:

   frida -U locationd --no-pause -l hook_durian.js

To set the DurianService etc. to call task, play a sound on the AirTag once.


Init Rose via BLE even on a non-UWB smartphone (run these in this order):

    d.initRoseWithParameters();
    d.setRoseRangingParameters();
    d.startRoseRanging();

    or just: d.testRose();


Send fully custom commands:

    d.performTaskWithCommand([1, 2, 3, 4, 5]);

Create and execute tasks directly in the CLI:

    d.performTaskByName('getSerialNumberTask');  // this works! but doesn't call sth because it's a dummyHawkeyeTask
    d.performTaskByName('startUnauthorizedSoundTask');  // this initiates gatt
    d.performTaskByName('fetchBatteryStatusTask');
    d.performTaskByName('stopSoundTask');
    d.performTaskByName('dumpNordicLogsTask');
    d.performTaskByName('fetchFirmwareVersionGATTTask');  // works and then triggers the fetchMultiStatusTask (?)

    d.performTaskByNameWithArg('testModeTask:', 1);  // meant for Hawkeye, though

    If ObjC stuff fails, which is already the case for creating some of these
    objects, locationd will hang and/or terminate :( No good feedback from the Frida
    ObjC runtime about that.

    Sometimes tasks are not executed on the AirTag or might fail, and some of these
    seem to crash the tag. Collecting logs etc. doesn't seem to work :(

Full list of pre-defined tasks:

    fetchFirmwareVersionTaskWithCrashLogs:
    fetchFirmwareVersionDeprecatedTask
    fetchCurrentKeyIndexTask
    fetchBatteryStatusTask
    fetchUserStatsTaskWithPersistence:
    unpairTask
    setUnauthorizedPlaySoundRateLimitTask:
    setCentralReferenceTimeTask
    setWildModeConfigurationTaskWithConfiguration:
    rollWildKeyTask
    setAbsoluteWildModeConfigurationTaskWithConfiguration:
    setTagTypeTaskWithType:
    startSoundSequenceTaskWithSequence:
    stopSoundTask
    startUnauthorizedSoundTask
    leashTask
    leashDisableTask
    setMaxConnectionsTaskWithCount:
    fetchMultiStatusTask
    fwdlAbortTask
    setObfuscatedIdentifierTaskWithIdentifier:
    setMutexAction:
    setMutexAction:withLatency:
    setNearOwnerTimeoutTaskWithTimeout:
    checkCrashesTask
    induceCrashTask
    setBatteryStatusTaskWithBatteryStatus:
    setKeyRotationTimeoutTaskWithTimeout:
    dumpNordicLogsTask
    dumpNordicCrashesTask
    dumpRoseLogsTask
    dumpRoseCrashesTask
    initRoseTaskWithParameters:
    stopRoseTaskWithParameters:
    setRoseRangingParametersTaskWithParameters:
    prepareForStartRoseRangingTask
    startRoseRangingTaskWithParameters:
    stopRoseRangingTask
    setAccelerometerSlopeModeConfigurationTaskWithConfiguration:
    setAccelerometerOrientationModeConfigurationTaskWithConfiguration:
    fetchAccelerometerSlopeModeConfigurationTask
    fetchAccelerometerOrientationModeConfigurationTask
    fetchAccelerometerModeTask
    dummyHawkeyeTask
    startSoundHawkeyeTask
    stopSoundHawkeyeTask
    enablePersistentConnectionsHawkeyeTask:
    setNearbyTimeoutHawkeyeTaskWithTimeout:
    unpairHawkeyeTask
    configureSeparatedStateHawkeyeTaskWithConfiguration:currentIndex:
    latchSeparatedKeyHawkeyeTask
    setMaxConnectionsHawkeyeTaskWithCount:
    setUtcHawkeyeTask
    getMultiStatusHawkeyeTask
    testModeTask:
    getCurrentPrimaryKeyTask
    getiCloudIdentifierTask
    getSerialNumberTask
    setKeyRotationTimeoutHawkeyeTaskWithTimeout:
    retrieveLogsHawkeyeTask
    resetHawkeyeTask
    setHawkeyeUTMotionConfigWithSeparatedUTTimeoutSeconds:separatedUTBackoffTimeoutSeconds:
    fetchProductDataGATTTask
    fetchManufacturerNameGATTTask
    fetchModelNameGATTTask
    fetchModelColorCodeGATTTask
    fetchAccessoryCategoryGATTTask
    fetchAccessoryCapabilitiesGATTTask
    fetchFirmwareVersionGATTTask
    fetchFindMyVersionGATTTask
    fetchBatteryTypeGATTTask
    fetchBatteryLevelGATTTask
    startNonOwnerSoundHawkeyeTask
    stopNonOwnerSoundHawkeyeTask
    sendUARPMessageTaskWithPayload:

*/


class Durian {

    constructor() {

        /*** INITIALIZE SCRIPT ***/
        this.ios_version = "arm64_14.7";  // TODO adjust version here!

        this.log_verbose = false;  // switch logging verbosity

        // global vars for the current device
        this.durian_service;
        this.durian_client;
        this.durian_device;
    }


    /*
    Script preparation, needs to be called in standalone usage.
    Separated from constructor for external script usage.
    */
    prepare() {

        var self = this;

        // some basic addresses
        self._locationd_base = Module.getBaseAddress('locationd');

        // Set the correct symbols
        self.setSymbols(self.ios_version);

        // hook sent/received bytes and show them
        self.showBytes();
        self.decodeIncomingBytes();

        // hook into exiting global vars
        self.hookServiceClientDevice();

        // print opcode list
        //self.printOpcodes();
    }

    // Backtrace helper function
    print_backtrace(ctx) {
        console.log('Backtrace:\n' +
        Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).join('\n') + '\n');
    }


    /*
     Show raw bytes as sent/received within locationd. Already misses the L2CAP metadata.
    */
    showBytes() {
        var self = this;

        var {CLDurianDeviceManager} = ObjC.classes;

        Interceptor.attach(CLDurianDeviceManager['- centralManager:didSendBytes:toPeripheral:withError:'].implementation, {
            onEnter: function(args) {
                console.log("  * Sent bytes!");
            }
        });

        Interceptor.attach(CLDurianDeviceManager['- centralManager:didReceiveData:fromPeripheral:'].implementation, {
            onEnter: function(args) {
                //self.print_backtrace(this.ctx);

                var len = args[3].add(8).readU32();
                var op = args[3].add(0x10).readU8();
                console.log("  * Received " + len + " bytes! Opcode " + op + " (" + self.getDurianOpcodeDescription(op) + ")");

                // log acknowledged opcode
                if (op == 0) {
                    op = args[3].add(0x11).readU8();
                    console.log("              > ACKed Opcode " + op + " (" + self.getDurianOpcodeDescription(op) + ")");
                }
                else if (op == 255) {
                    op = args[3].add(0x11).readU8();
                    console.log("              > NACKed Opcode " + op + " (" + self.getDurianOpcodeDescription(op) + ")");
                }

                // also log raw bytes
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

        var getOpcodeString = new NativeFunction(self._DurianOpcodeDescription, 'pointer', ['int64']);
        var desc = new ObjC.Object(getOpcodeString(opcode));
        return desc.toString();
    }

    getHawkeyeOpcodeDescription(opcode) {
        var self = this;
        var getOpcodeString = new NativeFunction(self._HawkeyeOpcodeDescription, 'pointer', ['int64']);
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

    decodeIncomingBytes() {

        var self = this;

        // -[CLDurianTask initWithCommand:desiredLatency:expectsResponse:completeOnPreemption:requiresMutex:]
        var {CLDurianTask} = ObjC.classes;
        Interceptor.attach(CLDurianTask['- initWithCommand:desiredLatency:expectsResponse:completeOnPreemption:requiresMutex:'].implementation, {
            onEnter: function(args) {

                console.log("  * CLDurianTask init");
                //console.log(args[0].readByteArray(0x10)); self
                var task = new ObjC.Object(args[0]);  // CLDurianTask
                //console.log("    v " + task.toString()); // not helpful, uninitialized task is always an Acknowledgment task
                //console.log(args[1].readByteArray(0x10)); SEL: 'initWithCommand:' ...

                if (args[2] != 0) {  // opcode can be 0, resulting in an access violation
                    var opcode = args[2].add(8).readInt();  // direct access to the opcode via the CLDurianCommand w/o ObjC API
                    console.log("     > opcode:               " + opcode + " (" + self.getDurianOpcodeDescription(opcode) + ")");  // command is 0: super + 8: opcode + 0x10: payload
                    console.log("     > desiredLatency:       " + args[3]);  // latency can also be negative
                    console.log("     > expectsResponse:      " + args[4]);
                    console.log("     > completeOnPreemption: " + args[5]);
                    console.log("     > requiresMutex:        " + args[6]);
                    // logging payload but length is defined by opcode so we don't know it here
                    //console.log(args[2].add(0x10).readByteArray(0x10));


                    // The task is already initiated with a pre-filled DurianCommand. This has an uint8 opcode
                    // as well as an NSData payload. The CLDurianCommand.-bytes returns both of these concatenated
                    // to NSData.
                    var command = new ObjC.Object(args[2]);  // CLDurianCommand
                    var {NSString} = ObjC.classes;
                    var bytes = command['- bytes'].implementation(command, NSString['stringWithString:']('-bytes'));
                    var b_len = bytes.add(8).readInt();
                    var raw_bytes = bytes.add(0x10).readByteArray(b_len);

                    // also log raw bytes
                    if (self.log_verbose) {
                        console.log(raw_bytes);
                    }

                    //self.print_backtrace(this.ctx);
                }

            }
        });

        var {CLDurianDevice} = ObjC.classes;

        // -[CLDurianDevice executeTask:](CLDurianDevice *self, SEL a2, id task)
        Interceptor.attach(CLDurianDevice['- executeTask:'].implementation, {
            onEnter: function(args) {
                console.log("  * CLDurianDevice executeTask");
                //self.print_backtrace(this.ctx);

            }
        });

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
    [CLDurianService dumpLogsOfType:forTag:forClient:] dumps logs, however, we can just create a task
    and then call -[CLDurianService performTask:forClient:onDevice:] ourselves.

    Types: 0 NordicLogs, 1 NordicCrashes, 2 RoseLogs, 3 RoseCrashes

    FIXME AirTag-side bug? Stops responding after this!
    */
    dumpLogs() {
        var self = this;
        self.performTaskByName('dumpNordicLogsTask');
        self.performTaskByName('dumpNordicCrashesTask');
        self.performTaskByName('dumpRoseLogsTask');
        self.performTaskByName('dumpRoseCrashesTask');
    }

    /*
    Four test modes and a default defined for Hawkeye:
    1 - fetchMultiStatus
    2 - setNearOwnerTimeout
    3+4 - stopSoundHawkeye
    default - nil task
    */
    testMode() {
        var self = this;
        var name = 'testModeTask:';
        var {CLDurianTask} = ObjC.classes;
        var {NSString} = ObjC.classes;
        var taskByName = CLDurianTask[name];
        // last task parameter is type
        var task = taskByName.implementation(CLDurianTask, NSString['stringWithString:'](name), 2);

        self.runTask(task);
    }

    /*
    Rose task is initialized with an 11 byte payload.
    Looked the same over multiple measurement rounds, might configure the remote MAC addr or
    similar.
    */
    initRoseWithParameters() {
        var self = this;

        // create Rose parameters
        // TODO reverse-engineer parameters, this one is taken from another log
        var params = self.allocNSData([0x0a, 0xe4, 0x97, 0xac, 0x4b, 0x6a, 0x02, 0x4e, 0xc5, 0x01, 0x01]);

        // last task parameter is payload appended to the opcode
        var task = self.createTaskByNameWithArg('initRoseTaskWithParameters:', params);
        self.runTask(task);

    }

    /*
    Rose ranging is then configured.
    This is called twice in an original log.
    */
    setRoseRangingParameters() {
        var self = this;

        // create Rose ranging parameters
        // TODO reverse-engineer parameters, this one is taken from another log
        var params = self.allocNSData([0x00, 0x00, 0x01, 0xa5, 0x44, 0x00, 0x00, 0x3b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);

        // last task parameter is payload appended to the opcode
        var task = self.createTaskByNameWithArg('setRoseRangingParametersTaskWithParameters:', params);
        self.runTask(task);

        // create Rose ranging parameters, round #2
        // needs a fresh object, is NACKed otherwise...
        // TODO reverse-engineer parameters, this one is taken from another log
        var params2 = self.allocNSData([0x04, 0x00, 0x00, 0x00, 0x00]);

        // last task parameter is payload appended to the opcode
        var task2 = self.createTaskByNameWithArg('setRoseRangingParametersTaskWithParameters:', params);
        self.runTask(task2);

    }

    /*
    Finally: start the actual Rose ranging
    */
    startRoseRanging() {
        var self = this;

        // create Rose ranging parameters
        // TODO reverse-engineer parameters, this one is taken from another log
        var params = self.allocNSData([0x52, 0x00]);

        // last task parameter is payload appended to the opcode
        var task = self.createTaskByNameWithArg('startRoseRangingTaskWithParameters:', params);
        self.runTask(task);
    }

    /*
    Call all Rose stuff in a row.
    */
    testRose() {
        var self = this;
        self.initRoseWithParameters();
        self.setRoseRangingParameters();
        self.startRoseRanging();
    }

    /*
    Play Sound Sequence but with custom params.

      * Parameter format as follows: valid sound sequences are 4-byte dwords
      [0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00]: play sound 1 once
      [0x01, 0x04, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00]: play sound 1 4x
      [0x02, 0x01, 0x23, 0x00] -> 1st byte is sound (0-7), 2nd byte is repetitions, 3rd byte is length, 4th byte is pause to next sound

    */
    playSound() {
        var self = this;

        // create sound sequence
        // parameter format as follows: valid sound sequences are 4-byte dwords, 0x104 and 0x205 for the default sound sequence
        //var params = self.allocNSData([0x04, 0x01, 0x00, 0x00, 0x05, 0x02, 0x00, 0x00]);  // original
        var params = self.allocNSData([0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);  // 2x short round of beeps

        // last task parameter is payload appended to the opcode
        var task = self.createTaskByNameWithArg('startSoundSequenceTaskWithSequence:', params);
        self.runTask(task);

    }

    playSoundSequence(sequence) {
        var self = this;
        var params = self.allocNSData(sequence);
        var task = self.createTaskByNameWithArg('startSoundSequenceTaskWithSequence:', params);
        self.runTask(task);

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
        return taskByName.implementation(CLDurianTask, NSString['stringWithString:'](name));
    }

    createTaskByNameWithArg(name, arg) {
        var {CLDurianTask} = ObjC.classes;
        var {NSString} = ObjC.classes;
        var taskByName = CLDurianTask[name];
        return taskByName.implementation(CLDurianTask, NSString['stringWithString:'](name), arg);
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

    Currently using some automatic detection, might need adjustments for arm64 vs arm64e.
    */
    setSymbols(ios_version) {

        var self = this;
        console.log(" * Automatically detecting symbols...");

        // at offset 28 in -[CLDurianTask opcodeDescription] there's a branch instruction to the function we need
        var {CLDurianTask} = ObjC.classes;
        var opcodeDescription = new NativePointer(CLDurianTask['- opcodeDescription'].implementation);
        self._DurianOpcodeDescription = new NativePointer(Instruction.parse(opcodeDescription.add(28)).operands.pop().value);
        console.log("  > _DurianOpcodeDesription " + self._DurianOpcodeDescription);


        // at offset 24 in -[CLHawkeyeTask opcodeDescription] there's a branch instruction to the function we need
        var {CLHawkeyeTask} = ObjC.classes;
        var opcodeDescription = new NativePointer(CLHawkeyeTask['- opcodeDescription'].implementation);
        self._HawkeyeOpcodeDescription = new NativePointer(Instruction.parse(opcodeDescription.add(24)).operands.pop().value);
        console.log("  > _HawkeyeOpcodeDescription " + self._HawkeyeOpcodeDescription);

    }


    // Export class methods for Frida
    // TODO not used with an external script yet...
    makeExports() {
        var self = this;
        return {
            setsymbols: (ios_version) => {return self.setSymbols(ios_version)},
            prepare: () => {return self.prepare()},
        }
    }

}

var d = new Durian();

// Prepare the script
d.prepare(); //TODO call this when standalone

// Required to interact with Python ...
rpc.exports = d.makeExports();
rpc.exports.d = Durian;