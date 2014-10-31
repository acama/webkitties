#!/usr/bin/env python2

import struct
import sys

MODX_SIZE = 0x20
MODIF_SIZE = 0x5c
MODIM_SIZE = 0x34

class ModExport:

    def __init__(self, data):
        self.size, \
        self.libver, \
        self.attrib, \
        self.num_fcn, \
        self.num_vars, \
        self.num_tls_vars, \
        self.mod_nid, \
        self.libname, \
        self.func_nid_tab, \
        self.func_entry_tab = struct.unpack("H" * 4 + "I" * 6, data)

    def __str__(self):
        buf = \
        """struct module_export
{
    u16_t size = 0x%x
    u16_t libver = 0x%x
    u16_t attrib = 0x%x
    u16_t numfuncs = 0x%x
    u16_t numvars = 0x%x
    u16_t num_tls_vars = 0x%x
    u32_t module_nid = 0x%x
    char * module_name = 0x%x
    u32_t * func_nid_tab = 0x%x
    void ** func_entry_tab = 0x%x
}""" % \
        (self.size, \
        self.libver, \
        self.attrib, \
        self.num_fcn, \
        self.num_vars, \
        self.num_tls_vars, \
        self.mod_nid, \
        self.libname, \
        self.func_nid_tab, \
        self.func_entry_tab)

        return buf
"""
TODO: !
Some ModImports are 0x24 instead of 0x34
as seen with SceNet's imports
class ModImportSmall:
"""

class ModImport:

    def __init__(self, data):
        self.size, \
        self.libver, \
        self.attrib, \
        self.num_fcn, \
        self.num_vars, \
        self.num_tls_vars, \
        self.reserved1, \
        self.mod_nid, \
        self.libname, \
        self.reserved2, \
        self.func_nid_tab, \
        self.func_entry_tab, \
        self.var_nid_tab, \
        self.var_entry_tab, \
        self.tls_nid_tab, \
        self.tls_entry_tab = struct.unpack("H" * 6 + "I" * 10, data)

    def __str__(self):
        buf = \
        """struct module_import
{
    u16_t size = 0x%x
    u16_t libver = 0x%x
    u16_t attrib = %s
    u16_t numfuncs = 0x%x
    u16_t numvars = 0x%x
    u16_t num_tls_vars = 0x%x
    u32_t reserved1 = 0x%x
    u32_t module_nid = 0x%x
    char * module_name = 0x%x
    u32_t reserved2 = 0x%x
    u32_t * func_nid_tab = 0x%x
    void ** func_entry_tab = 0x%x
    u32_t * var_nid_tab = 0x%x
    void ** var_entry_tab = 0x%x
    u32_t * tls_nid_tab = 0x%x
    void ** tls_entry_tab = 0x%x
}""" % \
        (self.size, \
        self.libver, \
        self.attrib, \
        self.num_fcn, \
        self.num_vars, \
        self.num_tls_vars, \
        self.reserved1, \
        self.mod_nid, \
        self.libname, \
        self.reserved2, \
        self.func_nid_tab, \
        self.func_entry_tab, \
        self.var_nid_tab, \
        self.var_entry_tab, \
        self.tls_nid_tab, \
        self.tls_entry_tab)

        return buf

class ModInfo:

    def __init__(self, data):
        self.modattr, \
        self.modver, \
        self.modname, \
        self.type, \
        self.gp_value, \
        self.ent_top, \
        self.ent_end, \
        self.stub_top, \
        self.stub_end, \
        self.module_nid, \
        self.unk38, \
        self.unk3c, \
        self.unk40, \
        self.mod_start, \
        self.mod_stop, \
        self.exidx_start, \
        self.exidx_end, \
        self.extab_start, \
        self.extab_end = struct.unpack("HH27sBI" + "I" * 14, data)

    def __str__(self):
        buf = \
        """struct module_info
{
    u16_t modattribute = 0x%x
    u16_t modversion = 0x%x
    char modname[27] = %s
    u8_t type = 0x%x
    void * gp_value = 0x%x
    u32_t ent_top = 0x%x
    u32_t ent_end = 0x%x
    u32_t stub_top = 0x%x
    u32_t stub_end = 0x%x
    u32_t module_nid = 0x%x
    u32_t field_38 = 0x%x
    u32_t field_3C = 0x%x
    u32_t field_40 = 0x%x
    u32_t mod_start = 0x%x
    u32_t mod_stop = 0x%x
    u32_t exidx_start = 0x%x
    u32_t exidx_end = 0x%x
    u32_t extab_start = 0x%x
    u32_t extab_end = 0x%x
}""" % \
        (self.modattr, \
        self.modver, \
        self.modname, \
        self.type, \
        self.gp_value, \
        self.ent_top, \
        self.ent_end, \
        self.stub_top, \
        self.stub_end, \
        self.module_nid, \
        self.unk38, \
        self.unk3c, \
        self.unk40, \
        self.mod_start, \
        self.mod_stop, \
        self.exidx_start, \
        self.exidx_end, \
        self.extab_start, \
        self.extab_end)
        
        return buf
