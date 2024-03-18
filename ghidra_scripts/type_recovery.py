import struct
from ghidra.program.model.symbol.SourceType import *
from ghidra.program.model.mem import *


def getAddressAt(address):
    return currentProgram.getAddressFactory().getAddress(hex(getInt(address)))

def remove_data(address, length):
    for i in range(length):
        removeDataAt(address.add(i))

def locate_pclntab_pe():
    pclntab_magic = [
        '\xfb\xff\xff\xff\x00\x00',
        '\xfa\xff\xff\xff\x00\x00',
        '\xf0\xff\xff\xff\x00\x00',
        '\xf1\xff\xff\xff\x00\x00'
        ]
    prog = getCurrentProgram()
    rdata = prog.getMemory().getBlock('.rdata')
    rdata_start = rdata.getStart()
    rdata_size = rdata.getSize()

    for magic in pclntab_magic:
        pclntab = rdata_start
        while pclntab != None:
            pclntab = findBytes(pclntab.add(1), magic)
            if pclntab is None:
                continue
            elif pclntab_check(pclntab):
                print("pclntab located")
                print(pclntab)
                return pclntab, magic
            else:
                continue
    return pclntab, None

def pclntab_check(addr):
    """this function checks the bytes just after the magic number is located to verify they foolow the structure
    of the pclntab """
    pc_arch_byte = getByte(addr.add(6)) #at offset 6 of the pclntab this byte tells architecture (1 for x86 4 for arm)
    pc_ptr_sz = getByte(addr.add(7)) #at offset 8 this byte determiens pointer size and shuld be 4 or 8
    
    if(pc_arch_byte != 1 and pc_arch_byte != 2 and pc_arch_byte != 4) or (pc_ptr_sz != 4 and pc_ptr_sz != 8):
        return False

    return True

def find_moduledata_pe(pclntab, magic):
    """
    pclntab_refs = getReferencesTo(pclntab) #moduledata will reference offset to pclntab
    print("find_module data executing...")  
    print("pclntab refs len: ", len(pclntab_refs))
    for i in range(len(pclntab_refs)):
        mod_data = pclntab_refs[i].getFromAddress()
        print(mod_data)
        if check_module_data(mod_data, magic):
            print("Module Data Found")
            print(mod_data)
        else:
            print("mod data not found")
    """
    prog = getCurrentProgram()
    data_start = prog.getMemory().getBlock('.data').getStart()
    data_end = prog.getMemory().getBlock('.data').getEnd()
    mod_data = data_start 
    while mod_data.compareTo(data_end) <= 0:
        s = struct.pack("<I", pclntab.getOffset())
        mod_data = findBytes(mod_data.add(1), s)
        if mod_data == None:
            return None

        if check_module_data(mod_data, magic):
            print("module data found at: ", mod_data)
            return mod_data

    return None

def check_module_data(addr, magic):
    offset = 22
    text = getAddressAt(addr.add(offset * ptr_size)) 
    mem = currentProgram.getMemory()    
    if text == mem.getBlock(".text").getStart():
        return True
    else:
        print("test failed")
        return False

def get_typelinks(mod_data, magic):
    #these are the numbers used in previous research for Go version 1.20+
    if magic == '\xf1\xff\xff\xff\x00\x00':
        offset = 37 
        offset1 = 44 
    elif magic == '\xf0\xff\xff\xff\x00\x00':
        offset = 35
        offset1 = 42
    else:
        offset = 37
        offset = 44
    #start of section containing custom type info
    s_type = getAddressAt(mod_data.add(offset * ptr_size))
    #end of section containing custom type info
    e_type = getAddressAt(mod_data.add((offset + 1) * ptr_size))
    #e_type = mod_data.add((offset + 1) * ptr_size)
    print("e_type: ", e_type)
    #offsets to go defined types
    typelinks = getAddressAt(mod_data.add(offset1 * ptr_size))
    #typelinks = mod_data.add(offset1 * ptr_size)
    print("Ptr_size: ", ptr_size)
    print("typelinks: ", typelinks)
    #num of type definitions
    num_types = getInt(mod_data.add((offset1 +1) * ptr_size))
    print("num types: ", num_types)
    return s_type, e_type, typelinks, num_types


def type_recovery(type_addr):
    if type_addr in recovered_types:
        print("type already recovered at ", type_addr.getOffset())
        return type_addr    
    recovered_types.append(type_addr)
    print("type recovered at addr: ", type_addr.getOffset())
    tflag_uncomm = getByte(type_addr.add(2*ptr_size+4))&0x01
    tflag_ex_star = getByte(type_addr.add(2*ptr_size+4))&0x02 #extra star flag
    kind = getByte(type_addr.add(2*ptr_size+7))&0x1F
    print "KIND: 0x%x" % kind
    name_off = getInt(type_addr.add(4 * ptr_size + 8))
    name_len = getByte(type_addr.add(name_off + len_off))
    name_addr = s_type.add(name_off + len_off + 1)
    remove_data(name_addr, name_len)
    name = createAsciiString(name_addr, name_len)
    if tflag_ex_star:
        name_type = name.getValue()[1:]
    else:
        name_type = name.getValue()
    print("name: ", name_type)
    createLabel(type_addr, name_type.replace(" ", "_"), 1)
    
    #Function type
    #// funcType represents a function type.
    #//
    #// A *rtype for each in and out parameter is stored in an array that
    #// directly follows the funcType (and possibly its uncommonType). So
    #// a function type with one method, one input, and one output is:
    #//
    #// struct {
    #//     funcType
    #//     uncommonType
    #//     [2]*rtype    // [0] is in, [1] is out
    #// }
    #type funcType struct {
    #   rtype
    #   inCount  uint16
    #   outCount uint16 // top bit is set if last input parameter is ...
    #}  
    if kind == 0x13:
        in_count = struct.unpack('<H',getBytes(type_addr.add(4 * ptr_size + 8 + 8), 2))[0]
        out_bytes = getBytes(type_addr.add(4 * ptr_size + 8 + 8 + 2), 2)
        #top bit is set if last param parameter is ...
        last_param = out_bytes[1] & 0x80
        out_bytes[1] = out_bytes[1] & 0x7F
        print last_param
        out_count = struct.unpack('<H',out_bytes)[0]
        params = []
        outputs= []
        for i in range(in_count):
            param  = getAddressAt(type_addr.add(4 * ptr_size + 8 + 8 + ptr_size + tflag_uncomm * 16 + i * ptr_size))
            recover_types(param)
            params.append(getSymbolAt(param).getName())
        for i in range(out_count):
            output = getAddressAt(type_address.add(4*ptr_size+8+8+ptr_size +tflag_uncomm*16 +in_count*ptr_size + i*ptr_size))
            recover_types(output)
            outputs.append(getSymbolAt(output).getName())
        if last_param == 0x80 and len(params) > 0:
            params[-1] = params[-1].replace("[]","...")
        setPreComment(type_address,"func(" + ", ".join(params) + ")" + " (" +  ", ".join(outputs) + ")")

def getAllTypes(typelinks, etypelinks, s_type):
    if typelinks is not None:
        p = typelinks
        while p != e_typelinks:
            type_offset = getInt(p)
            type_address = s_type.add(type_offset)
            type_recovery(type_address)
            p = p.add(4)
    print len(recovered_types)
    return len(recovered_types)

def main_pe():
    pclntab, magic = locate_pclntab_pe()    
    mod_data = find_moduledata_pe(pclntab, magic) 
    print(mod_data)
    s_type, e_type, typelinks, num_types = get_typelinks(mod_data, magic)
    e_typelinks = typelinks.add(num_types * 4)
    return typelinks, e_typelinks, s_type

recovered_types = []
ptr_size = currentProgram.getDefaultPointerSize()
len_off = 2 #this should be determined via a function but for 1.17+ this is the magic value
typelinks, e_typelinks, s_type = main_pe()
print("typelinks: ", typelinks, "e_typelinks: ", e_typelinks) 
getAllTypes(typelinks, e_typelinks, s_type)
