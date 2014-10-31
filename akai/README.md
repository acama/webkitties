akai 0.1
--------
An exploit of the webkit vuln that implements a minimal "SDK" for the Vita. Current supported versions are 3.15 and 3.18.
This can be useful for fuzzing functions, loading and dumping modules, exploring the file system and pretty much anything
else that is possible to do under the privileges of the Webkit process.

To use, first run
```
    chmod a+x serv.py
    ./serv.py
```
Then with the Vita browse to `http://<ipaddr>:8888`.

In `inc/api.js` you can find the list of functions that are currently supported and some examples can be found
in `inc/sample.js`.
The main stuff happens in `inc/sploit.js` and `inc/rop.js`.

This is what it should look like:
<img src="https://github.com/acama/webkitties/blob/master/akai/example.png">
