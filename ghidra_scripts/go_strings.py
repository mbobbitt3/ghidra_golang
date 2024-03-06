from ghidra.program.model.symbol.SourceType import *
from ghidra.program.model.mem import *
from ghidra.program.model.address import *
from ghidra.program.util import *
from ghidra.program.model.pcode import *

"""
def string_recovery():
	p = getCurrentProgram()
	rdata = p.getMemory().getBlock('.rdata')
	rd_start = rdata.getMinimumAddress()
	rd_end = rdata.getMaximumAddress()
	ptr_size = 8 #we are making assumpption for testing this is a 64 bit app
	dataConv = Data
	while rd_start <= rd_end:
		if rdata
"""

def getAddr(off):
	p = getCurrentProgram()
	return p.getAddressFactory().getDefaultAddressSpace().getAddress(off)

def dynamic_str_recovery():
	p = getCurrentProgram()
	fm = p.getFunctionManager()
	funcs = fm.getFunctions(True)
	lst = p.getListing()
	for f in funcs:
		if "main." in f.getName():
			f_body = f.getBody()
			insts = lst.getInstructions(f_body, True)
			while insts.hasNext():
				inst = insts.next() #first instruction init value for inst iterator
				if inst.getMnemonicString() == "LEA":
					pcode = inst.getPcode()
					for param in pcode:
			#			print("  {}".format(param))
						#if param.getOpcode() == 1: #int opcode for COPY operation
						inst_in = param.getInput(0) 
						if inst_in.isConstant():
							d_addr = inst_in.getAddress().getOffset()
							d_addr = getAddr(d_addr)
							data = getDataAt(d_addr)
							if data is not None and data.isPointer():
								str_len = getByte(d_addr.add(8))
								d = data.getValue()
								try:
									rec_string = createAsciiString(d, str_len)
									print(rec_string)
								except:
									print("unable to make string using PTR_DATA")

							else:
								print("elif hit")
								next_inst = insts.next()
								if next_inst.getMnemonicString() == "MOV":
									pcode = next_inst.getPcode()
									for param in pcode:
										nxt_inst_in = param.getInput(0)
										if nxt_inst_in.isConstant():
											str_len = nxt_inst_in.getOffset()
											try:
												print("updated ", nxt_inst_in.getOffset())
												print("updated ", d_addr)
												rec_string = createAsciiString(d_addr, str_len)
											except:
												print("unable to make string using const str_size")
												break
										else:
											break
								else:
									break
							#else:
							#	break
				
				else:
					continue
		
		else:
			continue



"""
	for f in funcs:
		f_start = f.getEntryPoint()
		f_end = f.getMaximumAddress()
"""

dynamic_str_recovery()
