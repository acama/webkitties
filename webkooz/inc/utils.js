/*
    This file contains helper functions such as functions
    used to send and get messages to the server...
*/

// global vars  
var _log0, _log, _dview;

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

// prints environment info
function writeEnvInfo()
{
	document.write(new Date().toTimeString() + "<br/>");
	document.write(navigator.userAgent + "<br/>");
	document.write(navigator.appName + " (" + navigator.platform + ")<br/><br/>");
}

// returns WebKit major version number
function getWebKitVersion(tmpl)
{
	var str = navigator.userAgent;
	if (!tmpl) tmpl = "WebKit/";
	var i = str.indexOf(tmpl);
	if (i >= 0) {
		i += tmpl.length;
		i = +str.substring(i,i+3);
		return isNaN(i) ? 0 : i;
	}
	return 0;
}

// creates new Uint32Array from Uint8Array's data
function U8toU32(u8)
{
	var len = u8.length;
	var u32 = new Uint32Array((len >>> 2) + (len % 4 ? 1:0));
	if (len > 1) {
		len--;
		for(var i=0; i <= len; i++){		
			u32[i >>> 2] += u8[i] << ((i%4)*8);		
		}
	}else{
		if (len) u32[0]	= u8[0];
	}
	return u32;
}	

// writes one array into another, and saves the old content
function exchangeArrays(aFrom, aTo, offs)
{
	var u, len = aFrom.length;
	for(var i=0; i < len; i++, offs++){
		u = aTo[offs];
		aTo[offs] = aFrom[i];
		aFrom[i] = u;
	}
}

// outputs uint32 as a comma-separated list of bytes
function getU8str(u)
{
	var str = "", s;
	for(var i=0; i < 4; i++, u >>>= 8) {
		s = (u & 0xff).toString(16);
		if (s.length < 2) s = "0" + s;
		str += s + (i < 3 ? ",":"");
	}
	
	return str;
}

// outputs the content of array object
function ArrayToU8String(arr, offs, len)
{
	var str = "["; 
	len += offs-1;	
	for(var i=offs; i <= len; i++){
	  	str += getU8str(arr[i]);
	  	str += i < len ? ", &nbsp;" + (i % 4 == 3 ? "<br/>":"") : "]";
	}
	return str;
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
