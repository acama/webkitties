webkitties
==========
Tools for fiddling with the Vita.

Dependencies
------------
python2
python-capstone

webkooz 0.1
-----------
Allows to play with the Vita's webkit process' memory by leveraging the webkit vuln.
To use, first start the server:

akai 0.1
--------
An exploit of the webkit vuln that implements a minimal "SDK" / testing framework for the Vita. Current supported versions are 3.15 and 3.18.
This can be useful for fuzzing functions, loading and dumping modules, exploring the file system and pretty much anything
else that is possible to do under the privileges of the Webkit process.

thanks
-------
@johntheropper, freebot - Helping with the exploit.
@yifanlu - Documentation.
@josh_axey, @archaemic, <unnamed>  - Lots of useful ideas.
