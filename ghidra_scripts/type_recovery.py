import struct
from ghidra.program.model.symbol.SourceType import *
from ghidra.program.model.mem import *


ptr_size = currentProgram.getDefaultPointerSize()
def getAddressAt(address):
	return currentProgram.getAddressFactory().getAddress(hex(getInt(address)))

def locate_pclntab_pe():
	pclntab_magic = ['\xfb\xff\xff\xff\x00\x00',
		'\xfa\xff\xff\xff\x00\x00',
		'\xf0\xff\xff\xff\x00\x00',
		'\xf1\xff\xff\xff\x00\x00',
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
			if pclntab_check(pclntab):
				print("pclntab located")
				print(pclntab)
				return pclntab, magic
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
	prog = getCurrentProgram()
	rdata = prog.getMemory().getBlock('.rdata')
	rdata_start = rdata.getStart()
	rdata_size = rdata.getSize()
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
			print("module data is located in: ",
				prog.getMemory().getBlock(mod_data).getName()
			)
			return mod_data

	return None

def check_module_data(addr, magic):
	offset = 22
	text = getAddressAt(addr.add(offset * ptr_size)) 
	mem = currentProgram.getMemory()	
	print("check_module_data on: ", addr)
	if text == mem.getBlock(".text").getStart():
		return True
	else:
		print("test failed")
		return False

def main_pe():
	pclntab, magic = locate_pclntab_pe()	
	print(pclntab, magic)
	find_moduledata_pe(pclntab, magic) 
main_pe()
