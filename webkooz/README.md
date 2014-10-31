vitadays
========

Dependencies
------------
python2
python-capstone

webkooz 0.1
-----------
Allows to play with the Vita's webkit process' memory by leveraging the webkit vuln.
To use, first start the server:
```
    chmod a+x serv.py
    ./serv.py
```
Then with the Vita browse to `http://<ipaddr>:8888`.
If all goes well you will see some output from the `serv.py` script. 
When you see `%> ` it means that initialization is done.
The supported commands are:
- **x** `addr` `len` : to display `len` bytes from `addr` in a hex-editor-like fashion
- **dis** `addr` `len` `mode` : to disassemble `len` bytes from `addr` in `mode` (thumb or arm, latter is default)
- **dump** `addr` `len` `fname` : to dump `len` bytes from `addr` to `fname`
- **ss** `begaddr` `endaddr` `pattern`: to search for the string `pattern` in [`begaddr`, `endaddr`[
- **reload** : to reload/reset everything
- **scanback** `addr` `step` : to scan back starting from `addr` with a step of `step` until the Vita crashes 
- **dispim** `begaddr` `n`: display `n` formatted module imports starting from `begaddr`
- **dispx** `begaddr` `n`: display `n` formatted module exports starting from `begaddr`
- **dispminf** `begaddr`: display a formatted module\_info starting from `begaddr`
- **scanm** `begaddr` : scan for a module\_info starting from `begaddr`
- **exit** : to exit
