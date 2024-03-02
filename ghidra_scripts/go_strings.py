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
	addr = getAddr(0x00483bc0)
	f = fm.getFunctionContaining(addr)
	lst = p.getListing()
	f_body = f.getBody()
	insts = lst.getInstructions(f_body, True)
	while insts.hasNext():
		inst = insts.next() #first instruction init value for inst iterator
		if inst.getMnemonicString() == "LEA":
			pcode = inst.getPcode()
			print("{}".format(inst))
			for param in pcode:
	#			print("  {}".format(param))
				if param.getOpcode() == 1: #int opcode for COPY operation
					inst_in = param.getInput(0) 
					if inst_in.isConstant():
						d_addr = inst_in.getAddress().getOffset()
						d_addr = getAddr(d_addr)
						data = getDataAt(d_addr)
						if data is not None and data.isPointer():
							str_len = getByte(d_addr.add(8))
							d = data.getValue()
							try:
								print(str_len)
								rec_string = createAsciiString(d, str_len)
								print(rec_string)
							except:
								print("unable to make string")
								continue
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
