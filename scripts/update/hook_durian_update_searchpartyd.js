/*
Hooking into searchpartyd and other daemons related to AirTags. Never ending story :(
These hooks are so generic that they work on all daemons that use a SPBeacon that
contains the AirTag info like serial number, version, etc.

Attach as follows:

   frida -U searchpartyd --no-pause -l hook_durian_update_searchpartyd.js

Can trigger a new firmware update by setting a wrong version number.


TODO trigger directly

Aug 16 01:18:30 searchpartyd[14857] <Notice>: Scheduling firmware update check with frequency: 9000.0, grace period: 1800.0
Aug 16 01:18:30 searchpartyd[14857] <Notice>: Schedule a firmware update check 300 seconds later (reason: paired)

-> most likely possible via XPC

Aug 10 22:11:59 searchpartyd[1454] <Notice>: Opened [TXN:com.apple.icloud.searchpartyd.BeaconManagerService.firmware-update-after-pairing.7D3FEC81-A882-4A7A-BDAE-FF494D67B6F5]

All the swift stuff etc. complicates hooking anything manually :(


*/


class Durian {

    constructor() {

        /*** INITIALIZE SCRIPT ***/
        this.ios_version = "arm64_14.7";  // adjust iOS version here! (nothing version-specificc so far...)

        // 1.0.276 latest version
        this.durian_version_string = '1.0.225';  // outdated firmware version

        this.durian_serial = 'TROLOLOLOLOL'; // some serial, whatever

        this.log_verbose = false;  // switch logging verbosity

        // global vars for the current device
        this.beacon;

    }



    /*
    Script preparation, needs to be called in standalone usage.
    Separated from constructor for external script usage.
    */
    prepare() {

        var self = this;

        // some basic addresses
        self._searchpartyd_base = Module.getBaseAddress('searchpartyd');

        // Set the correct symbols
        self.setSymbols(self.ios_version);

        // overwrite version etc. in the SPBeacon
        self.overwriteSPBeacons();

        // fake that we're an intenralBuild
        self.fakeInternalBuild();

        // debug some stuff
        self.hookSchedule();

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
        Faking that this is an internalBuild :)
        Much more logging on every tag found, is requested for sooo many log entries.
    */
    fakeInternalBuild() {

        var self = this;

        var {FMSystemInfo_ios} = ObjC.classes;

        self.t = Memory.alloc(32); // "true" pointer that works with NSDictionary or so
        //self.t.writeInt(1);
        // okay whatever this one works...
        self.t.writeByteArray([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);

        Interceptor.attach(FMSystemInfo_ios['- isInternalBuild'].implementation, {
            onEnter: function(args) {
                //console.log(" ! Faking isInternalBuild=True");
            },
            onLeave: function(r) {
                this.context.x0 = self.t;
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
    [iOS Device::searchpartyd]-> Scheduling update! Reason: 0x1
    0x16fd4e7a0
               0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
    00000000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    00000010  01 63 7c 23 00 00 00 c0 ac 63 7c 23 02 00 00 c0  .c|#.....c|#....
    Backtrace:
    0x100780038 searchpartyd!0x44038 (0x100044038)
    0x10078009c searchpartyd!0x4409c (0x10004409c)
    0x10090c880 searchpartyd!0x1d0880 (0x1001d0880)
    0x1008256b0 searchpartyd!0xe96b0 (0x1000e96b0)
    0x1ab55a2b0 libdispatch.dylib!_dispatch_call_block_and_release
    0x1ab55b298 libdispatch.dylib!_dispatch_client_callout
    0x1ab537344 libdispatch.dylib!_dispatch_lane_serial_drain$VARIANT$armv81
    0x1ab537e60 libdispatch.dylib!_dispatch_lane_invoke$VARIANT$armv81
    0x1ab54166c libdispatch.dylib!_dispatch_workloop_worker_thread
    0x1f3e555bc libsystem_pthread.dylib!_pthread_wqthread

    Then repeated 2x for:
    Scheduling update! Reason: 0x7

    then some wait time then
    Scheduling update! Reason: 0x6


    */
    hookSchedule() {
        var self = this;

/*
        Interceptor.attach(self._schedule_update_addr, {
            onEnter: function(args) {
                console.log("Scheduling update! Reason: " + args[0]);
                //this.context.x0 = 6; // doesn't help to set it to 6... :/
                console.log(args[1]);  // TODO no idea what this is but no ObjC?
                //console.log(args[1].readByteArray(0x20));
                //console.log(new ObjC.Object(args[1]));

                //self.print_backtrace(this.context);

            }
        });
        */

/*

        Interceptor.attach(self._searchpartyd_base.add(0x44088), {
            onEnter: function(args) {
                console.log("Beacon observed...");
                console.log(args[1]);  // ??
                console.log(new ObjC.Object(args[1])); //searchpartyd.FirmwareUpdateService

            }
        });
*/

    }




    /*
    Version-specific symbols, needs to be adjusted for every version.
    */
    setSymbols(ios_version) {

        var self = this;

        // tested on an iPhone 8
        if (ios_version == "arm64_14.7") {
            console.log("  * Set symbols to pre-A12 iOS 14.7");

            /*
            self._schedule_update_addr = self._searchpartyd_base.add(0x41640);
            self._schedule_update = new NativeFunction(self._schedule_update_addr, 'pointer', ['char', 'pointer']);
            */


        }
        else {
            console.log("  ! undefined symbols");
        }


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

// Prepare the target function
d.prepare(); //TODO call this when standalone

// Required to interact with Python ...
// Yep even the standalone fuzzer should use this because calling the fuzzer
// directly will timeout on large payloads
rpc.exports = d.makeExports();
rpc.exports.d = Durian;
