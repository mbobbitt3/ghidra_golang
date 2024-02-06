from ghidra.program.model.symbol.SourceType import *
from ghidra.program.model.mem import *

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
			if pclntab == None:
				continue
			if pclntab_check(pclntab):
				print("pclntab located")
				print(pclntab)
				return pclntab
	return pclntab

def pclntab_check(addr):
	"""this function checks the bytes just after the magic number is located to verify they foolow the structure
	of the pclntab """
	pc_arch_byte = getByte(addr.add(6)) #at offset 6 of the pclntab this byte tells architecture (1 for x86 4 for arm)
	pc_ptr_sz = getByte(addr.add(7)) #at offset 8 this byte determiens pointer size and shuld be 4 or 8
	
	if(pc_arch_byte != 1 and pc_arch_byte != 2 and pc_arch_byte != 4) or (pc_ptr_sz != 4 and pc_ptr_sz != 8):
		return False
	
	return True
#def 
locate_pclntab_pe()
