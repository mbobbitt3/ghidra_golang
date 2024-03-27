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
def parse_pclntab(pclntab_addr):
	prog = getCurrentProgram()
	ptr_sz = getByte(pclntab_addr.add(7))
	if ptr_sz == 8:
		#we use long because long is of size 8 bytes
		num_funcs = getLong(pclntab_addr.add(8)) #num_funcs in prog
		start_text = getLong(pclntab_addr.add(8 + 2 * ptr_sz)) #start of text addr
		offset = getLong(pclntab_addr.add(8 + 3 * ptr_sz)) #offset to function name table
		name_tab = pclntab.add(offset) #addr of function name table
		offset = getLong(pclntab_addr.add(8 + 7 * ptr_sz)) #offset within function table

	else:
		#we use int because int is of size 4 bytes
		num_funcs = getInt(pclntab_addr.add(8)) #num_funcs in prog
		start_text = getInt(pclntab_addr.add(8 + 2 * ptr_sz)) #start of text addr
		offset = getInt(pclntab_addr.add(8 + 3 * ptr_sz)) #offset to function name table
		name_tab = pclntab.add(offset) #addr of function name table
		offset = getInt(pclntab_addr.add(8 + 7 * ptr_sz)) #offset within function table

	func_table = pclntab_addr.add(offset)
	ft = func_table #shorter for referencing object
	ftab_field_sz = 4 #4 fields per entry in table
	for i in range(num_funcs):
		f_addr = prog.getAddressFactory().getAddress(hex(getInt(ft) + start_text).rstrip("L"))
		ft = ft.add(ftab_field_sz)
		fdata_off = getInt(ft)
		ft = ft.add(ftab_field_sz)
		name_ptr = func_table.add(fdata_off + ftab_field_sz)
		name_addr = name_tab.add(getInt(name_ptr))
		f_name = getDataAt(name_addr)
		if f_name is None:
			try:
				f_name = createAsciiString(name_addr)
			except:
				print("data unable to be created at {0}".format(name_addr))
				continue
		f = getFunctionAt(f_addr)
		if f is not None:
			fname_old  =  f.getName()
			f.setName(f_name.getValue().replace(" ", ""), USER_DEFINED)
		else:
			f = createFunction(f_addr, f_name.getValue())
pclntab = locate_pclntab_pe()
parse_pclntab(pclntab)
