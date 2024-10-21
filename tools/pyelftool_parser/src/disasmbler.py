
import re
from capstone.x86 import *
from elftools.elf.elffile import ELFFile
from capstone import *
from elftools.elf.sections import (
    NoteSection, SymbolTableSection, SymbolTableIndexSection
)
from debug import log
class disasmbler:
    def __init__(self, path, entry_function):
        self.path = path
        self.inst = dict()                  ## mapping address to inst encoding
        self.symbol = dict()                ## mapping address to symbol
        self.symbol_address = dict()        ## mapping symbol to address
        self.syn_invocation = dict()        ## mapping the synchronization symbol address to target function
        self.invo_jmp_table = dict()        ## hardcode the invocation address for fetching pc 
        self.thread_list = dict()           ## hardcode the call/jmp for fetching pc 
        self.slm_ipithd_create_address = 0  ## hardcode the thread function for scheduler.
        self.capmgr_initthd_create_address = 0
        self.function_call_address = 0
        self.entry_function = entry_function
        self.entry_function_list = list()    ## need to put the cosrt_s into it.
        self.entry_pc = 0
        self.exit_pc = 0
        self.invocation_function = list() ## record the invocation function here.
        self.acquire_stack_size = 0
        self.init_done_address = 0
        self.init_done_end_address = 0
                
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

    def disasminstpass(self, md, ops, addr):    ## disasm the instruction into a list, setting up the entry/exit pc.
        pc_flag = 0
        stack_flag = 0
        
        for inst in md.disasm(ops, addr):
            self.inst[inst.address] = (inst)
            if (inst.address in self.symbol):   ## it is to catch the next symbol start, also for catch the last inst. @minghwu: I think it could have a better way to do this.
                pc_flag = 0
                
            if (inst.address == self.entry_pc): ## when it is entry point, set the flag = 1 to catch exitpoint.
                pc_flag = 1
            if (pc_flag == 1):                  ## catch the point until the next symbol, means it is exit point.
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
    
    def disasmthreadpointer(self, md, ops, addr):
        thread_function_list = list()
        for inst in md.disasm(ops, addr):
            if inst.address in self.symbol and self.symbol[inst.address] == "slm_ipithd_create": 
                self.slm_ipithd_create_address = inst.address
                thread_function_list.append(self.slm_ipithd_create_address)
            if inst.address in self.symbol and self.symbol[inst.address] == "capmgr_initthd_create": 
                self.capmgr_initthd_create_address = inst.address
                thread_function_list.append(self.capmgr_initthd_create_address)                
        flag = 0
        for inst in md.disasm(ops, addr):
            if inst.address in self.symbol and self.symbol[inst.address] == "cos_upcall_fn":
                flag = 1
            if flag == 1 and inst.id == X86_INS_CALL:
                for i in inst.operands:
                    if i.type != X86_OP_MEM and i.type != X86_OP_IMM: ## mean it is not the call instruction we want, because it is memory call.
                        if len(thread_function_list) > 0:
                            self.function_call_address = inst.address
                            self.thread_list= thread_function_list
                            flag = 0

    def disasminst(self):  ## decode the inst for execute
        with open(self.path, 'rb') as f:
            elf = ELFFile(f)
            code = elf.get_section_by_name('.text')  ## text section
            ops = code.data()
            addr = code['sh_addr']
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True
            self.disasminstpass(md, ops, addr)      ## disasm the instruction into a list, setting up the entry/exit pc.
            self.disasmthreadpointer(md, ops, addr) ## hardcode the dynamic thread.
            
            code = elf.get_section_by_name('.rodata')
            if code:
                ops = code.data()
                addr = code['sh_addr']
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                md.detail = True
                self.disasminstpass(md, ops, addr)      ## disasm the instruction into a list, setting up the entry/exit pc.
                self.disasmthreadpointer(md, ops, addr) ## hardcode the dynamic thread.
            
            
            code = elf.get_section_by_name('.plt.sec')
            if code:
                ops = code.data()
                addr = code['sh_addr']
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                md.detail = True
                self.disasminstpass(md, ops, addr)      ## disasm the instruction into a list, setting up the entry/exit pc.
                self.disasmthreadpointer(md, ops, addr) ## hardcode the dynamic thread.

    def disasmsymbol(self):
        with open(self.path, 'rb') as f:
            e = ELFFile(f)
            symbol_tables = [ s for s in e.iter_sections()
                         if isinstance(s, SymbolTableSection)]
            for section in symbol_tables:
                for symbol in section.iter_symbols():
                    self.symbol[symbol['st_value']] = symbol.name
                    self.symbol_address[symbol.name] = symbol['st_value']
                    log(symbol.name, symbol['st_value'])
                    if(symbol.name == self.entry_function): ## set up the entry pc.
                        self.entry_pc = symbol['st_value']
                        log("Set up entry point")
                        log(hex(self.entry_pc))

    def disasminvocation(self):  ## change the cosrt_extern to cosrt_c_;
        with open(self.path, 'rb') as f:
            e = ELFFile(f)
            symbol_tables = [ s for s in e.iter_sections()
                         if isinstance(s, SymbolTableSection)]
            for section in symbol_tables:
                for symbol in section.iter_symbols():
                    if "__cosrt_s" in symbol.name:
                        if symbol.name.replace("__cosrt_s_", "") in self.invocation_function:
                            self.entry_function_list.append(symbol.name)
                    
                    if "__cosrt_extern" in symbol.name:
                        if symbol.name.replace("__cosrt_extern_", "") in self.invocation_function:
                            if symbol.name.replace("__cosrt_extern", "__cosrt_c") in self.symbol.keys():   ## check is there mapping __cosrt_extern_* to __cosrt_c_* invocation
                                log("invocation1")
                                self.syn_invocation[symbol['st_value']] =  self.symbol_address[symbol.name.replace("__cosrt_extern", "__cosrt_c")]
                                log(self.syn_invocation[symbol.name])
                            else:
                                log("invocation2")
                                log(symbol.name)
                                self.syn_invocation[symbol['st_value']] = self.symbol_address["__cosrt_c_cosrtdefault"]
                    if "__cosrt_extern_init_done" in symbol.name:
                        self.init_done_address = symbol['st_value'] 
                    if "__cosrt_extern_init_parallel_await_init":
                        self.init_parallel_await_init_address = symbol['st_value']

    def disasminvotable(self):  ## hardcode synchronization invocation in a table to jump. 
        with open(self.path, 'rb') as f:
            elf = ELFFile(f)
            code = elf.get_section_by_name('.text')
            ops = code.data()
            addr = code['sh_addr']
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True
            for inst in md.disasm(ops, addr):
                if inst.address in self.syn_invocation: ## build up the invocation table.
                    self.invo_jmp_table[inst.address] = self.syn_invocation[inst.address]
    