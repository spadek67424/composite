import sys
import register
import execute
import math
import os
import re
from debug import loginst, log, logresult, logstack, logrust, logerror
from capstone.x86 import *
from elftools.elf.elffile import ELFFile
from capstone import *
from elftools.elf.sections import (
    NoteSection, SymbolTableSection, SymbolTableIndexSection
)
class disassembler:
    def __init__(self, path, entry_function):
        self.path = path
        self.inst = dict()              ## mapping address to inst encoding
        self.symbol = dict()            ## mapping address to symbol
        self.symbol_address = dict()    ## mapping symbol to address
        self.syn_invocation = dict()    ## mapping the synchronization symbol address to target function
        self.invo_jmp_table =dict()   ## hardcode the invocation address for fetching pc 
        self.call_jmp_table =dict()   ## hardcode the call/jmp for fetching pc 
        
        self.vertex = dict()            ## construct the calling graph
        self.entry_function = entry_function
        self.entry_function_list = list()    ## need to put the cosrt_s into it.
        self.entry_pc = 0
        self.exit_pc = 0
        self.invocation_function = list() ## record the invocation function here.
        self.acquire_stack_size = 0
    def disasmstubs(self, file_path):
        stub_pattern = re.compile(r'cos_asm_stub\((\w+)\)')
        stub_indirect_pattern = re.compile(r'cos_asm_stub_indirect\((\w+)\)')
        stubs = []
        stub_indirects = []

        # Open and read the file
        with open(file_path, 'r') as file:
            content = file.read()

            # Find all cos_asm_stub matches
            stubs = stub_pattern.findall(content)

            # Find all cos_asm_stub_indirect matches
            stub_indirects = stub_indirect_pattern.findall(content)

        # Output the results
        log("cos_asm_stub functions:")
        for stub in stubs:
            self.invocation_function.append(stub)

        log("\ncos_asm_stub_indirect functions:")
        for stub_indirect in stub_indirects:
            self.invocation_function.append(stub_indirect)

    def disasminst(self):  ## decode the inst for execute
        pc_flag = 0
        stack_flag = 0
        with open(self.path, 'rb') as f:
            elf = ELFFile(f)
            code = elf.get_section_by_name('.text')
            ops = code.data()
            addr = code['sh_addr']
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True
            for inst in md.disasm(ops, addr):
                self.inst[inst.address] = (inst)
                if (inst.address in self.symbol):  ## it is to catch the next symbol start. @minghwu: I think it could have a better way to do this.
                    pc_flag = 0
                if (inst.address == self.entry_pc): ## when it is entry point, set the flag = 1 to catch exitpoint.
                    pc_flag = 1
                if (pc_flag == 1):               ## catch the point until the next symbol, means it is exit point.
                    self.exit_pc = inst.address
                    
                if inst.address in self.symbol and self.symbol[inst.address] == "custom_acquire_stack":  ## try to catch the movabs which is in the acquire_stack function to set rsp.
                    stack_flag = 1
                     
                if stack_flag == 1 and inst.id == X86_INS_MOVABS:
                    stack_flag = 0
                    tempstack = 0
                    for i in inst.operands:
                        if i.type == X86_OP_IMM:
                            tempstack = i.imm
                    self.acquire_stack_size = tempstack
                    log("stack_size_begin")
                    log(self.acquire_stack_size)
                
                log(f'0x{inst.address:x}:\t{inst.mnemonic}\t{inst.op_str}')

    def disasmsymbol(self):
        with open(self.path, 'rb') as f:
            e = ELFFile(f)
            symbol_tables = [ s for s in e.iter_sections()
                         if isinstance(s, SymbolTableSection)]
            for section in symbol_tables:
                for symbol in section.iter_symbols():
                    self.symbol[symbol['st_value']] = symbol.name
                    self.symbol_address[symbol.name] = symbol['st_value']
                    self.vertex[symbol['st_value']] = symbol.name
                    log(symbol.name, symbol['st_value'])
                    if(symbol.name == self.entry_function): ## set up the entry pc.
                        self.entry_pc = symbol['st_value']
                        log("Set up entry point")
                        log(hex(self.entry_pc))
                    if(symbol.name == 'custom_acquire_stack'):
                        self.acquire_stack_address = symbol['st_value']
    
    def disasminvocation(self):  ## change the cosrt_extern to cosrt_c_;
        with open(self.path, 'rb') as f:
            e = ELFFile(f)
            symbol_tables = [ s for s in e.iter_sections()
                         if isinstance(s, SymbolTableSection)]
            for section in symbol_tables:
                for symbol in section.iter_symbols():
                    
                    if "__cosrt_s" in symbol.name:
                        if symbol.name.remove("__cosrt_s_", "") in self.invocation_function:
                            self.entry_function_list.append(symbol.name)
                    
                    if "__cosrt_extern" in symbol.name:
                        if symbol.name.remove("__cosrt_extern_", "") in self.invocation_function:
                            if symbol.name.replace("__cosrt_extern", "__cosrt_c") in self.symbol.keys():   ## check is their mapping __cosrt_extern_* to __cosrt_c_* invocation
                                log("invocation1")
                                self.syn_invocation[symbol['st_value']] =  self.symbol_address[symbol.name.replace("__cosrt_extern", "__cosrt_c")]
                                log(self.syn_invocation[symbol.name])
                            else:
                                log("invocation2")
                                log(symbol.name)
                                self.syn_invocation[symbol['st_value']] = self.symbol_address["__cosrt_c_cosrtdefault"]
                                                  
    def disasmcalljmp(self):  ## I hardcode a lot of jump call address here for execution and function pointer. 
        
        # print("syn_invocation")
        # print(self.syn_invocation) 
        with open(self.path, 'rb') as f:
            elf = ELFFile(f)
            code = elf.get_section_by_name('.text')
            ops = code.data()
            addr = code['sh_addr']
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True
            flagimm = 0
            
            for inst in md.disasm(ops, addr): ## decode the call and jmp address here.
                if inst.address in self.syn_invocation:
                    self.invo_jmp_table[inst.address] = self.syn_invocation[inst.address]
                elif len(inst.operands) == 1 and (inst.id == X86_INS_CALL or inst.id == X86_INS_JMP or inst.id == X86_INS_JE or inst.id == X86_INS_JLE or inst.id == X86_INS_JGE or inst.id == X86_INS_JG or inst.id == X86_INS_JNE): ## check it is not function pointer and hardcode the call/jmp table.
                    for i in inst.operands:
                        if i.type == X86_OP_IMM: ## check it is not function pointer.
                            flagimm = 1
                    if flagimm == 1:            ## build up the static call/jmp table
                        self.call_jmp_table[inst.address] = int(inst.op_str, 0)
                    if flagimm == 0:            ## synchronization invocation call would be here, @@@@ WARNING booter has problem.
                        logerror("dynamic address or function pointer.")
                    flagimm = 0

    
              
    def sym_analyzer(self):
        sym_info = {}
        with open(self.path, 'rb') as f:
            e = ELFFile(f)
            symbol_tables = [ s for s in e.iter_sections()
                         if isinstance(s, SymbolTableSection)]
            for section in symbol_tables:
                for symbol in section.iter_symbols():
                    if (symbol['st_size'] == 0):
                        continue   
                    sym_info[symbol.name] = {
                        'address': symbol['st_value'],
                        'size': symbol['st_size'],
                        'padding': 0   
                    }
            #sort by adress to ensure contiguous symbols
            sorted_names = sorted(sym_info.keys(),
            key=lambda name: sym_info[name]['address'],
            reverse=False)
            #assign padding based on difference in address
            for i, name in enumerate(sorted_names):
                if (i == 0):
                    continue
                prev_sym = sym_info[sorted_names[i - 1]]
                cur_sym = sym_info[name]
                prev_sym['padding'] = cur_sym['address'] - prev_sym['address'] - prev_sym['size']
                #sort by size
            sorted_names = sorted(sym_info.keys(),key=lambda name: sym_info[name]['size'], reverse=True)
            #print symbols in order of size with padding
            for name in sorted_names[:10]:
                cur_sym = sym_info[name]
                log(
                    f"Name: {name}, Address: {hex(cur_sym['address'])}, Size: {hex(cur_sym['size'])}, Padding: {hex(cur_sym['padding'])}"
                )
    
class parser:
    def __init__(self, symbol, inst, register, execute, exit_pc, acquire_stack_address, invo_jmp_table, call_jmp_table):
        self.symbol = symbol 
        self.inst = inst
        self.stacklist = []
        self.stackfunction = []
        self.register = register
        self.execute = execute
        self.invo_jmp_table = invo_jmp_table
        self.call_jmp_table = call_jmp_table
        self.edge = set()
        self.vertex = set()
        self.index = 0
        self.exit_pc = exit_pc
        self.retjmppc = 0
        self.retjmpflag = 0
        self.acquire_stack_address = acquire_stack_address
        self.retcallpc = []
        self.seenlist = [] ## handle the while loop jmp.
        
    def stack_analyzer(self):
        address_list = list(self.inst.keys())  ## a list for instruction address.
        address_list.append(-1) ## dummy value for last iteration.
        self.index = address_list.index(self.register.reg["pc"]) ## index for each instruction address.
        nextinstRip = list(self.inst.keys())
        nextinstRip.append(-1) ## dummy value for last iteration.
        while(self.register.reg["pc"] != self.exit_pc):
            self.register.updaterip(nextinstRip[self.index + 1 if self.index + 1 in nextinstRip else self.index]) ## catch the rip for memory instruction.
            if self.register.reg["call_or_jmp"] == 0 and self.register.reg["pc"] in self.symbol.keys():  ## check function block (as basic block but we use function as unit.)
                self.stackfunction.append(self.symbol[self.register.reg["pc"]])
                logstack(self.symbol[self.register.reg["pc"]])   ## TODO: here is error.
                self.register.updatestackreg()
                self.stacklist.append(self.register.reg["stack"])
                self.register.cleanstack()
                self.register.cleaninvocation()
                self.register.resetrsp() 
                ###### Graph
                vertexfrom = self.register.reg["pc"]
                self.vertex.add(vertexfrom)
                ######
            self.register.cleancalljmp()  # clean the call inst.
            self.execute.exe(self.inst[self.register.reg["pc"]], self.edge, vertexfrom)
            self.register.updatestackreg()
            #### fetch next instruction pc
            print("fdsafds")
            print(address_list[self.index])
            print(self.invo_jmp_table)
            if address_list[self.index] in self.invo_jmp_table:  ### hardcode the call/jmp table, we jmp to target address.
                self.retcallpc.append(address_list[self.index + 1])
                self.edge.add((hex(address_list[self.index]), hex(self.invo_jmp_table[address_list[self.index]])))
                self.index = address_list.index(self.invo_jmp_table[address_list[self.index]])
                self.register.reg["rsp"] -= 8 ## because the invocation call.
            elif (self.register.reg["invo"] == 0 and self.index == address_list.index(self.register.reg["pc"])):  ## fetch next instruction
                if self.inst[self.register.reg["pc"]].id == (X86_INS_RET): ## ret instruction, go to return address.
                    self.index = address_list.index(self.retcallpc.pop()) if len(self.retcallpc) > 0 else self.index + 1
                elif address_list[self.index + 1] in self.symbol.keys() and self.retjmpflag == 1: ## Assuming the return to return address if going to the end of function.
                    self.index = address_list.index(self.retjmppc)
                    self.retjmpflag = 0
                else:
                    self.index = self.index + 1
            else:     ## handle the call and jmp instruction
                if self.inst[address_list[self.index]].id == (X86_INS_CALL): ## if this is call, append the return address to stack.
                    self.retcallpc.append(address_list[self.index + 1])
                    if self.register.reg["invo"] == 1:  ## handle unknown function pointer.
                        self.index = self.index + 1
                    else:
                        self.index = address_list.index(self.register.reg["pc"])
                    self.register.reg["invo"] = 0 ## clean the invo reg.        
                else:  ## handle jmp inst 
                    self.retjmppc = address_list[self.index + 1]  ## set the return point
                    self.retjmpflag = 1
                    if self.register.reg["pc"] not in self.seenlist: ## handle the while loop of jmp.
                        self.index = address_list.index(self.register.reg["pc"])
                        self.seenlist.append(self.register.reg["pc"])
                    else:  ## unknown function pointer
                        self.index = self.index + 1
                    self.register.reg["invo"] = 0 ## clean the invo reg.
            ####
            print(self.index)
            self.register.reg["pc"] = address_list[self.index] ## Setting the pc from index.
            
        self.stacklist.append(self.register.reg["stack"])
        self.stacklist = self.stacklist[1:]
        return (self.stackfunction,self.stacklist)
    
def cleanresult(parser, dissasmbler): ## remove the custom_acquire_stack function from the result.
    index = 0
    
    for i in parser.stackfunction:
        if i == "custom_acquire_stack":
            parser.stackfunction.remove("custom_acquire_stack")
            del parser.stacklist[index]
            return
        index = index + 1
    
    
def driver(parser):
    
    parser.stack_analyzer()
    
    return parser.stacklist

def PowerOf2(N):
    # Calculate log2 of N
    a = int(math.log2(N))
 
    # If 2^a is equal to N, return N
    if 2**a == N:
        return a
     
    # Return 2^(a + 1)
    return a + 1

if __name__ == '__main__':
    
    ## path = "../testbench/composite/system_binaries/cos_build-test/global.sched/sched.pfprr_quantum_static.global.sched"
    ## path = "/home/minghwu/work/minghwu/composite/system_binaries/cos_build-test/global.ping/tests.unit_pingpong.global.ping"
    
    if len(sys.argv) >=3:
        entry_function = sys.argv[2]
    else:
        entry_function = "__cosrt_upcall_entry"
    if len(sys.argv) >=2:
        path = sys.argv[1]
    else:
        path = "../../system_binaries/cos_build-test/global.ping/tests.unit_pingpong.global.ping"
    if path.split(".")[-1] == "ping":
        stub_path = "../../src/components/interface/" + "pong" + "/stubs/stubs.S"
    else:
        stub_path = "../../src/components/interface/" + path.split(".")[-1] + "/stubs/stubs.S"
    assert(os.path.exists(stub_path))
    
    
    
    
    disassembler = disassembler(path, entry_function)
    disassembler.disasmstubs(stub_path)
    disassembler.disasmsymbol()
    disassembler.disasminvocation()  ##TODO @minghwu we also need to consider the cosrt_s_ from here as entry point.
    disassembler.disasminst()
    disassembler.disasmcalljmp()
    
    exit()
    
    
    disassembler.sym_analyzer()
    log("program entry:"+ str(disassembler.entry_pc))
    log("program exit:"+ str(disassembler.exit_pc))
    log("program stacksize"+ str(disassembler.acquire_stack_size))
    register = register.register(disassembler.acquire_stack_size)
    register.reg["pc"] = disassembler.entry_pc
    execute = execute.execute(register)
    parser = parser(disassembler.symbol, 
                    disassembler.inst, 
                    register,
                    execute, 
                    disassembler.exit_pc, 
                    disassembler.acquire_stack_address,
                    disassembler.invo_jmp_table,
                    disassembler.call_jmp_table)
    
    driver(parser)
    
    logresult(parser.stackfunction)
    i = 0
    for j in parser.stackfunction:
        logresult(j)
        logresult(i)
        i = i + 1
    logresult(parser.stacklist)
    i = 0
    for j in parser.stacklist:
        logresult(i)
        logresult(j)
        i = i + 1
    logresult(parser.edge)
    
    stacksize = min(parser.stacklist)
    logresult(stacksize)
    logrust(PowerOf2(abs(stacksize)))
    
    
