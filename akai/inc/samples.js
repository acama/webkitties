/*
   This file contains sample code
*/

/*
   Connect to ip on given port and
   send msg
*/

function socket_send(ip, port, msg){

    var scenet = libraries.SceNet.functions;
    var sockaddr = allocate_memory(32); 

    mymemset(sockaddr, 0, SIZEOF_SIN);

    aspace[sockaddr] = SIZEOF_SIN;
    aspace[sockaddr + 1] = SCE_NET_AF_INET;

    var PORT = port;
    logdbg("Calling nethtons()");
    var r = scenet.sceNetHtons(PORT); 
    logdbg("-> 0x" + r.toString(16) + "\n"); 
    aspace16[((sockaddr + 2) / 2)] = r;

    aspace32[(sockaddr + 4) / 4] = inet_addr(ip);

    var dbgname = "test_socket\x00";
    var dbgnameaddr = allocate_memory(dbgname.length);

    mymemcpy(dbgnameaddr, dbgname, dbgname.length);

    logdbg("Calling SceNetSocket()");
    var sockfd = scenet.sceNetSocket(dbgnameaddr, SCE_NET_AF_INET, SCE_NET_SOCK_STREAM, 0);
    logdbg("-> 0x" + sockfd.toString(16) + "\n"); 

    logdbg("Calling SceNetConnect()");
    var r = scenet.sceNetConnect(sockfd, sockaddr, SIZEOF_SIN); 
    logdbg("-> 0x" + r.toString(16) + "\n"); 

    var msgaddr = allocate_memory(msg.length);

    mymemcpy(msgaddr, msg, msg.length);

    logdbg("Calling SceNetSend()");
    var sent = scenet.sceNetSend(sockfd, msgaddr, msg.length, 0);
    logdbg("-> 0x" + sent.toString(16) + "\n"); 

    logdbg("Calling SceNetClose()");
    var sent = scenet.sceNetSocketClose(sockfd, 0, 0, 0);
    logdbg("-> 0x" + sent.toString(16) + "\n"); 
}

/*
    List Directory
*/
function list_dir(dirname){
    var scekernel = libraries.SceLibKernel.functions;

    var dirname_a = allocate_memory(0x20);
    var dirlist = allocate_memory(0x1000);

    mymemcpy(dirname_a, dirname, dirname.length);

    var fd = scekernel.sceIoDopen(dirname_a);
    fd = Int(fd);
    if(fd < 0){
        logdbg("sceIoDopen() failed");
        return;
    }

    logdbg("Listing: " + dirname);
    while (scekernel.sceIoDread(fd, dirlist) > 0){
        myprintf(dirlist + 0x58);
    }
    logdbg("-\n");
}

/*
    Retrieve the file fname
    and save to dumps/loc_name
*/
function retrieve_file(fname, loc_name){
    var scelibc = libraries.SceLibc.functions;
    var BUFSIZE = 0x1000;

    var fname_a = allocate_memory(fname.length + 1);
    mymemcpy(fname_a, fname + "\x00", fname.length);

    var mode = "r";
    var mode_a = allocate_memory(mode.length + 1);
    mymemcpy(mode_a, mode + "\x00", mode.length);

    var fp = scelibc.fopen(fname_a, mode_a);
    fp = Int(fp);
    if(fp == 0){
        logdbg("fopen() failed");
        return; 
    }

    var buf = allocate_memory(BUFSIZE);
    var n = 0;
    while((n = scelibc.fread(buf, 1, BUFSIZE, fp)) > 0){
        logdbg("-> 0x" + n.toString(16));
        var bytes = get_bytes(aspace, buf, n);
        sendcmsg("dump", buf, bytes, loc_name); 
    }

}
