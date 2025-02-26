
import re
from capstone.x86 import *
from elftools.elf.elffile import ELFFile
from capstone import *
from elftools.elf.sections import (
    NoteSection, SymbolTableSection, SymbolTableIndexSection
)
from debug import log, logterminator
class disasmbler:
    def __init__(self, path, entry_function):
        self.path = path
        self.inst = dict()                  ## mapping address to inst encoding
        self.symbol = dict()                ## including the symbol's name only.  @@ minghwu these mappings should be able to be optimized.
        self.symbol_address = dict()        ## mapping symbol to address
        self.syn_invocation = dict()        ## mapping the synchronization symbol address to target function
        self.inst_address_to_symbol_name = dict()  ## mapping the inst address to symbol name
        self.invo_jmp_table = dict()        ## hardcode the invocation address for fetching pc 
        self.thread_list = dict()           ## hardcode the call/jmp for fetching pc 
        self.slm_ipithd_create_address = 0  ## hardcode the thread function for scheduler.
        self.capmgr_initthd_create_address = 0
        self.function_call_address = 0
        self.entry_function = entry_function
        self.entry_function_list = list()   ## need to put the cosrt_s into it.
        self.entry_pc = 0
        self.exit_pc = 0
        self.invocation_function = list()   ## record the invocation function here.
        self.acquire_stack_size = 0
                
    def disasmstubs(self, file_paths):
        for file_path in file_paths:
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
                log(stub)
                self.invocation_function.append(stub)
    
            log("\ncos_asm_stub_indirect functions:")
            for stub_indirect in stub_indirects:
                log(stub_indirect)
                self.invocation_function.append(stub_indirect)
    def disasminstpass(self, md, ops, addr):    ## disasm the instruction into a list, setting up the entry/exit pc.
        pc_flag = 0
        stack_flag = 0
        function_now = 0
        for inst in md.disasm(ops, addr):
            self.inst[inst.address] = (inst)
            
            if inst.address in self.symbol:
                function_now = self.symbol[inst.address]
            self.inst_address_to_symbol_name[inst.address] = function_now
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
    def disasmthreadpointer(self, md, ops, addr):   ## TODO(@minghwu): it is really ugly hardcode. We need to do it in composite to make function pointer to section.
        thread_function_list = list()
        for inst in md.disasm(ops, addr):
            if inst.address in self.symbol and self.symbol[inst.address] == "slm_ipithd_create": 
                self.slm_ipithd_create_address = inst.address
                thread_function_list.append(self.slm_ipithd_create_address)
                
            if inst.address in self.symbol and self.symbol[inst.address] == "capmgr_initthd_create": 
                self.capmgr_initthd_create_address = inst.address
                thread_function_list.append(self.capmgr_initthd_create_address) 
                
            if inst.address in self.symbol and self.symbol[inst.address] == "slm_idle":
                self.slm_idle_address = inst.address
                thread_function_list.append(self.slm_idle_address)
                
            if inst.address in self.symbol and self.symbol[inst.address] == "slm_ipi_process":
                self.slm_ipi_process_address = inst.address
                thread_function_list.append(self.slm_ipi_process_address)

            if inst.address in self.symbol and self.symbol[inst.address] == "bounceback":
                self.bounceback_address = inst.address
                thread_function_list.append(self.bounceback_address)

            if inst.address in self.symbol and self.symbol[inst.address] == "async_thd_parent_perf":
                self.async_thd_parent_perf_address = inst.address
                thread_function_list.append(self.async_thd_parent_perf_address)

            if inst.address in self.symbol and self.symbol[inst.address] == "async_thd_parent":
                self.async_thd_parent_address = inst.address
                thread_function_list.append(self.async_thd_parent_address)

            if inst.address in self.symbol and self.symbol[inst.address] == "async_thd_fn":
                self.async_thd_fn_address = inst.address
                thread_function_list.append(self.async_thd_fn_address)

            if inst.address in self.symbol and self.symbol[inst.address] == "spinner":
                self.spinner_address = inst.address
                thread_function_list.append(self.spinner_address)

            if inst.address in self.symbol and self.symbol[inst.address] == "test_thd_arg":
                self.test_thd_arg_address = inst.address
                thread_function_list.append(self.test_thd_arg_address)

            if inst.address in self.symbol and self.symbol[inst.address] == "thd_fn_mthds_ring":
                self.thd_fn_mthds_ring_address = inst.address
                thread_function_list.append(self.thd_fn_mthds_ring_address)

            if inst.address in self.symbol and self.symbol[inst.address] == "thd_fn_mthds_classic":
                self.thd_fn_mthds_classic_address = inst.address
                thread_function_list.append(self.thd_fn_mthds_classic_address)

            if inst.address in self.symbol and self.symbol[inst.address] == "test_thds_reg":
                self.test_thds_reg_address = inst.address
                thread_function_list.append(self.test_thds_reg_address)

            if inst.address in self.symbol and self.symbol[inst.address] == "thds_fpu":
                self.thds_fpu_address = inst.address
                thread_function_list.append(self.thds_fpu_address)

            if inst.address in self.symbol and self.symbol[inst.address] == "term_fn":
                self.term_fn_address = inst.address
                thread_function_list.append(self.term_fn_address)

            if inst.address in self.symbol and self.symbol[inst.address] == "test_rcv_fn":
                self.test_rcv_fn_address = inst.address
                thread_function_list.append(self.test_rcv_fn_address)

            if inst.address in self.symbol and self.symbol[inst.address] == "timer_fn":
                self.timer_fn_address = inst.address
                thread_function_list.append(self.timer_fn_address)

            if inst.address in self.symbol and self.symbol[inst.address] == "pingpong_fn":
                self.pingpong_fn_address = inst.address
                thread_function_list.append(self.pingpong_fn_address)

            if inst.address in self.symbol and self.symbol[inst.address] == "interleave_fn":
                self.interleave_fn_address = inst.address
                thread_function_list.append(self.interleave_fn_address)

            if inst.address in self.symbol and self.symbol[inst.address] == "done_fn":
                self.done_fn_address = inst.address
                thread_function_list.append(self.done_fn_address)

            if inst.address in self.symbol and self.symbol[inst.address] == "cos_aepthd_fn":
                self.cos_aepthd_fn_address = inst.address
                thread_function_list.append(self.cos_aepthd_fn_address)
        
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
    def check_stack_alloca_loop_error(self, md, ops, addr):  #### detection of stack allocation loop. Hardcode the lea, sub 0x1000, or, cmp,
        flaglea = 0                                    #### @@ TODO: minghwu. It is really a pretty bad hardcode, I need to think about it again. 
        flagsub = 0
        flagor = 0
        flagcmp = 0
        index = 0
        for inst in md.disasm(ops, addr):
            if inst.address in self.symbol:
                flaglea = 0
                flagsub = 0
                flagor = 0
                flagcmp = 0
                index = 0
                flagrsp = 0
            if inst.id == X86_INS_LEA:
                (regs_read, regs_write) = inst.regs_access()
                for r in regs_read:  ## catch the implicity read register of stack,  
                    if "rsp" in inst.reg_name(r):
                        flagrsp = 1
                for r in regs_write: ## catch the implicity write register of stack
                    if "rsp" in inst.reg_name(r):
                        flagrsp = 1
                if flagrsp:
                    flaglea = 1
            if inst.id == X86_INS_SUB:
                (regs_read, regs_write) = inst.regs_access()
                for r in regs_read:  ## catch the implicity read register of stack,  
                    if "rsp" in inst.reg_name(r):
                        flagrsp = 1
                for r in regs_write: ## catch the implicity write register of stack
                    if "rsp" in inst.reg_name(r):
                        flagrsp = 1
                for i in inst.operands:
                    if i.type == X86_OP_IMM:
                        imm = i.imm
                        flagimm = 1
                if  flaglea and flagrsp and flagimm and imm == 0x1000:
                    flagsub = 1
                    index = 1
                else:
                    index = 0
                    flagsub = 0
                    flagor = 0
                    flagcmp = 0
                    index = 0
            flagrsp = 0
            if flagsub and inst.id == X86_INS_OR and index == 1:
                (regs_read, regs_write) = inst.regs_access()
                for r in regs_read:  ## catch the implicity read register of stack,  
                    if "rsp" in inst.reg_name(r):
                        flagrsp = 1
                for r in regs_write: ## catch the implicity write register of stack
                    if "rsp" in inst.reg_name(r):
                        flagrsp = 1
                if flagrsp:
                    flagor = 1
                    index = 2
                else:
                    flagsub = 0
                    flagor = 0
                    flagcmp = 0
                    index = 0

            flagrsp = 0
            if flagor and inst.id == X86_INS_CMP:
                (regs_read, regs_write) = inst.regs_access()
                for r in regs_read:  ## catch the implicity read register of stack,
                    if "rsp" in inst.reg_name(r):
                        flagrsp = 1
                for r in regs_write: ## catch the implicity write register of stack
                    if "rsp" in inst.reg_name(r):
                        flagrsp = 1
                if flagrsp:
                    flagcmp = 1
                    index = 3
                else:
                    flagsub = 0
                    flagor = 0
                    flagcmp = 0
                    index = 0
            if flagcmp and inst.id == X86_INS_JNE and index == 3:
                logterminator("ERROR : Stack allocation loop Detected.")
    def check_dynamic_stack_alloca(self, md, ops, addr):
        for inst in md.disasm(ops, addr):
            pattern1 = r"\b([a-zA-Z_]\w*)\s*\*\s*4\s*\+\s*([a-zA-Z_]\w*)\b" ## "(register) * 4 + register"
            pattern2 = r"\b([a-zA-Z_]\w*)\s*\*\s*4\s*\+\s*(0x[0-9A-Fa-f]+)\b"  ## "(register) * 4 + (0xnumber)"
            if inst.id == X86_INS_LEA:
                matches = re.findall(pattern1, inst.op_str)
                matches2 = re.findall(pattern2, inst.op_str)
                if matches or matches2:
                    logterminator("ERROR : Dynamic stack allocation Detected.")
                
        
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
            self.check_stack_alloca_loop_error(md, ops, addr)
            self.check_dynamic_stack_alloca(md, ops, addr)
            
            code = elf.get_section_by_name('.rodata')
            if code:
                ops = code.data()
                addr = code['sh_addr']
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                md.detail = True
                self.disasminstpass(md, ops, addr)      ## disasm the instruction into a list, setting up the entry/exit pc.
                self.disasmthreadpointer(md, ops, addr) ## hardcode the dynamic thread.
                self.check_stack_alloca_loop_error(md, ops, addr)
                self.check_dynamic_stack_alloca(md, ops, addr)
            
            code = elf.get_section_by_name('.plt.sec')
            if code:
                ops = code.data()
                addr = code['sh_addr']
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                md.detail = True
                self.disasminstpass(md, ops, addr)      ## disasm the instruction into a list, setting up the entry/exit pc.
                self.disasmthreadpointer(md, ops, addr) ## hardcode the dynamic thread.
                self.check_stack_alloca_loop_error(md, ops, addr)
                self.check_dynamic_stack_alloca(md, ops, addr)
                
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
                            if symbol.name.replace("__cosrt_extern", "__cosrt_c") in self.symbol_address.keys():   ## check is there mapping __cosrt_extern_* to __cosrt_c_* invocation
                                log("invocation to" + symbol.name.replace("__cosrt_extern", "__cosrt_c"))
                                self.syn_invocation[symbol['st_value']] =  self.symbol_address[symbol.name.replace("__cosrt_extern", "__cosrt_c")]
                            else:
                                log("invocation to cosrtdefault")
                                self.syn_invocation[symbol['st_value']] = self.symbol_address["__cosrt_c_cosrtdefault"]

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
    