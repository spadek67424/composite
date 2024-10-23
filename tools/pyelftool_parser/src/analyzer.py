import sys
import disasmbler
import register
import execute
import jmp_class
import math
import os
import re
import subprocess
from debug import loginst, log, logresult, logstack, logrust, logerror, logcall, logterminator
from capstone.x86 import *
from elftools.elf.elffile import ELFFile
from capstone import *
from elftools.elf.sections import (
    NoteSection, SymbolTableSection, SymbolTableIndexSection
)

## @@ TODO: check the stack status is same when enter/return into/from function, SEE ABI.
class parser:
    def __init__(self, symbol, inst, register, execute, entry_pc, exit_pc, invo_jmp_table, thread_list, function_call_address, inst_address_to_symbol_name):
        self.symbol = symbol 
        self.inst = inst
        self.stacklist = []
        self.stackfunction = []
        self.register = register
        self.execute = execute
        self.invo_jmp_table = invo_jmp_table
        self.thread_list = thread_list
        self.function_call_address = function_call_address
        self.inst_address_to_symbol_name = inst_address_to_symbol_name
        self.edge = set()
        self.vertex = set()
        self.index = 0
        self.entry_pc = entry_pc
        self.exit_pc = exit_pc
        self.retjmppc = 0
        self.retjmpflag = 0
        self.retcallpc = []
        self.seenlist = [] ## handle the while loop jmp.
        self.JtypeClass = []

    def check_exe_virtual_return(self, address_list, function_now): ## virtual ret.
        if address_list[self.index + 1] in self.symbol.keys() : ## have a virtual return address for some function does not have ret.
            self.execute.exe(-1)  
            if self.execute.retflag == 1:
                log("virtual return")
                return 1
        return 0
    
    def IsJtypeInst(self, inst):
        return inst.id == X86_INS_CALL or inst.id == X86_INS_JMP or inst.id == X86_INS_JE or inst.id == X86_INS_JLE or inst.id == X86_INS_JGE or inst.id == X86_INS_JG or inst.id == X86_INS_JNE
    
    def stack_analyzer(self):
        address_list = list(self.inst.keys())  ## a list for instruction address.
        address_list.append(-1) ## dummy value for last iteration.
        self.index = address_list.index(self.register.reg["pc"]) ## index for each instruction address.
        nextinstRip = list(self.inst.keys())
        nextinstRip.append(-1) ## dummy value for last iteration.
        self.register.updaterip(nextinstRip[self.index + 1 if self.index + 1 in nextinstRip else self.index]) ## catch the rip for memory instruction.
        function_now = 0
        while(self.register.reg["pc"] != self.exit_pc):
            #### execute 
            if (self.register.reg["pc"] == -1):
                self.execute.exe(-1)
            else:
                self.execute.exe(self.inst[self.register.reg["pc"]])
            self.register.updatesmaxstackreg()
            
            #### fetch next instruction pc and commit
            if address_list[self.index] in self.seenlist: ## Already seen this address before, going to context switch to last branch.
                self.seenlist.remove(address_list[self.index])
                if len(self.JtypeClass) > 0:
                    branchnode = self.JtypeClass.pop()
                    self.index = branchnode.returnPCIndex
                    self.register.reg["stack"] = branchnode.stack
                    self.register.reg["rsp"] = branchnode.rsp
                    self.register.reg["rspbegin"] = branchnode.rspbegin
                else:
                    self.index = self.index + 1
                    
            elif address_list[self.index] in self.invo_jmp_table:         ## looking up hardcode the synchronization table, we jmp to target address.
                if self.inst[address_list[self.index]].id == X86_INS_CALL:
                    self.JtypeClass.append(jmp_class.JmpContext(self.index+1, self.index, self.register.reg["stack"], self.register.reg["rspbegin"], self.register.reg["rsp"]))
                if self.IsJtypeInst(self.inst[address_list[self.index]]):
                    self.JtypeClass.append(jmp_class.JmpContext(self.index+1, self.index, self.register.reg["stack"], self.register.reg["rspbegin"], self.register.reg["rsp"]))
                self.seenlist.append(address_list[self.index])
                if self.invo_jmp_table[address_list[self.index]] in self.symbol:
                    self.edge.add((self.inst_address_to_symbol_name[address_list[self.index]], self.inst_address_to_symbol_name[self.invo_jmp_table[address_list[self.index]]]))
                self.index = address_list.index(self.invo_jmp_table[address_list[self.index]])
                self.register.reg["call_or_jmp"] = 0 ## clean the call/jmp indicator. 
                log("fastpace with hardcode invocation table.")

            elif address_list[self.index] == self.function_call_address:  ## looking up hardcode the thread address, and jmp to target address.
                self.JtypeClass.append(jmp_class.JmpContext(self.index + 1, self.index, self.register.reg["stack"], self.register.reg["rspbegin"], self.register.reg["rsp"]))
                for thread_function_address in self.thread_list:
                    self.JtypeClass.append(jmp_class.JmpContext(address_list.index(thread_function_address), self.index, self.register.reg["stack"], self.register.reg["rspbegin"], self.register.reg["rsp"]))
                    if thread_function_address in self.symbol:
                        self.edge.add((self.inst_address_to_symbol_name[address_list[self.index]], self.inst_address_to_symbol_name[thread_function_address]))
                        print("bbb")
                        print(function_now)
                self.seenlist.append(address_list[self.index])
                self.register.reg["call_or_jmp"] = 0     ## clean the call/jmp indicator. 
                log("fastpace with hardcode thread table.")

            elif self.register.reg["call_or_jmp"] == 0:  ## if it is not jmp/call inst, try to fetch next instruction
                if self.inst[self.register.reg["pc"]].id == (X86_INS_RET): ## ret instruction, go to return address.
                    if len(self.JtypeClass) > 0:
                        branchnode = self.JtypeClass.pop()
                        self.index = branchnode.returnPCIndex
                        self.register.reg["stack"] = branchnode.stack
                        self.register.reg["rsp"] = branchnode.rsp
                        self.register.reg["rspbegin"] = branchnode.rspbegin
                    else:
                        self.index = self.index + 1
                else:
                    if self.check_exe_virtual_return(address_list, function_now):
                        if len(self.JtypeClass) > 0:
                            branchnode = self.JtypeClass.pop()
                            self.index = branchnode.returnPCIndex
                            self.register.reg["stack"] = branchnode.stack
                            self.register.reg["rsp"] = branchnode.rsp
                            self.register.reg["rspbegin"] = branchnode.rspbegin
                        else:
                            self.index = self.index +1
                    else:
                        self.index = self.index + 1
            else:     ## Time to handle Call/Jmp inst if it is not catched by fast pass.
                if self.inst[address_list[self.index]].id == (X86_INS_CALL): ## handle call inst, if it is not catched by the fast pass.
                    if self.register.reg["call_or_jmp"] == 2:  ## handle unknown function pointer.
                        logerror("Here is dynamic call")
                        logerror(address_list[self.index], self.inst[address_list[self.index]].mnemonic, self.inst[address_list[self.index]].op_str)
                        if self.check_exe_virtual_return(address_list, function_now):
                            if len(self.JtypeClass) > 0:
                                branchnode = self.JtypeClass.pop()
                                self.index = branchnode.returnPCIndex
                                self.register.reg["stack"] = branchnode.stack
                                self.register.reg["rsp"] = branchnode.rsp
                                self.register.reg["rspbegin"] = branchnode.rspbegin
                            else:
                                self.index = self.index + 1
                        else:
                            self.index = self.index + 1                             
                    elif address_list[self.index] not in self.seenlist:
                        self.JtypeClass.append(jmp_class.JmpContext(self.index+1, self.index, self.register.reg["stack"], self.register.reg["rspbegin"], self.register.reg["rsp"]))
                        self.seenlist.append(address_list[self.index])
                        if self.register.reg["pc"] in self.symbol:
                            self.edge.add((self.inst_address_to_symbol_name[address_list[self.index]], self.inst_address_to_symbol_name[self.register.reg["pc"]]))
                        self.index = address_list.index(self.register.reg["pc"])
                    else: ## It is seen, time to pop.
                        self.seenlist.remove(address_list[self.index])
                        if len(self.JtypeClass) > 0:
                            branchnode = self.JtypeClass.pop()
                            self.index = branchnode.returnPCIndex
                            self.register.reg["stack"] = branchnode.stack
                            self.register.reg["rsp"] = branchnode.rsp
                            self.register.reg["rspbegin"] = branchnode.rspbegin
                            self.register.reg["call_or_jmp"] = 0 ## clean the invo reg.
                        else:
                            self.index = self.index + 1
                else:  ## handle jmp inst, if it is not catched by the fast pass.
                    if self.register.reg["call_or_jmp"] == 2:  ## unknown function pointer or already seen
                        logerror("Here is dynamic jmp")
                        logerror(address_list[self.index], self.inst[address_list[self.index]].mnemonic, self.inst[address_list[self.index]].op_str)
                        if self.check_exe_virtual_return(address_list, function_now):
                            if len(self.JtypeClass) > 0:
                                branchnode = self.JtypeClass.pop()
                                self.index = branchnode.returnPCIndex
                                self.register.reg["stack"] = branchnode.stack
                                self.register.reg["rsp"] = branchnode.rsp
                                self.register.reg["rspbegin"] = branchnode.rspbegin
                            else:
                                self.index = self.index + 1
                        else:
                            self.index = self.index + 1
                    elif address_list[self.index] not in self.seenlist:
                        self.seenlist.append(address_list[self.index])
                        self.JtypeClass.append(jmp_class.JmpContext(self.index+1, self.index, self.register.reg["stack"], self.register.reg["rspbegin"], self.register.reg["rsp"]))
                        if self.register.reg["pc"] in self.symbol:
                            self.edge.add((self.inst_address_to_symbol_name[address_list[self.index]], self.inst_address_to_symbol_name[self.register.reg["pc"]]))

                            print("ddd")
                            print(function_now)
                        self.index = address_list.index(self.register.reg["pc"])
                    else: ## it is seen, time to pop.
                        self.seenlist.remove(address_list[self.index])
                        if len(self.JtypeClass) > 0:
                            branchnode = self.JtypeClass.pop()
                            self.index = branchnode.returnPCIndex
                            self.register.reg["stack"] = branchnode.stack
                            self.register.reg["rsp"] = branchnode.rsp
                            self.register.reg["rspbegin"] = branchnode.rspbegin
                        else:
                            self.index = self.index + 1
            #### commit the instruction.
            self.register.reg["call_or_jmp"] = 0 ## clean the call/jmp reg.
            self.register.updatesmaxstackreg()
            self.register.reg["pc"] = address_list[self.index]
            if (self.register.reg["pc"] == -1):
                if len(self.JtypeClass) > 0:
                    branchnode = self.JtypeClass.pop()
                    self.index = branchnode.returnPCIndex
                    self.register.reg["stack"] = branchnode.stack
                    self.register.reg["rsp"] = branchnode.rsp
                    self.register.reg["rspbegin"] = branchnode.rspbegin
                    self.register.reg["call_or_jmp"] = 0 ## clean the invo reg.
                    self.register.reg["pc"] = address_list[self.index]
                else:
                    self.index = self.index + 1
            if self.register.reg["pc"] in self.symbol:
                self.stackfunction.append(self.symbol[self.register.reg["pc"]])
                self.stacklist.append(self.register.reg["stack"])
            self.register.updaterip(nextinstRip[self.index + 1 if self.index + 1 in nextinstRip else self.index]) ## catch the rip for memory instruction.
            ########
        return (self.stackfunction,self.stacklist)
    
    def find_cycle_directed(self, edges): ## Try to find Recusion.
        # Step 1: Build adjacency list from the (From, To) edges
        graph = {}

        # Create the graph (adjacency list) from the edge list
        for from_node, to_node in edges:
            if from_node not in graph:
                graph[from_node] = []
            graph[from_node].append(to_node)
            if to_node not in graph:
                graph[to_node] = []

        # Step 2: Use DFS to detect cycles and track the nodes involved
        def dfs(node, visited, rec_stack, path):
            visited[node] = True
            rec_stack[node] = True  # mark the node in recursion stack
            path.append(node)  # track the current path

            # explore neighbors
            for neighbor in graph[node]:
                if not visited[neighbor]:
                    if dfs(neighbor, visited, rec_stack, path):  # cycle found
                        return True
                elif rec_stack[neighbor]:  # back edge found (cycle)
                    # Cycle detected, return the path leading to the cycle
                    path.append(neighbor)
                    return True

            rec_stack[node] = False  # remove node from recursion stack
            path.pop()  # backtrack
            return False

        # Initialize visited and recursion stack dictionaries
        visited = {node: False for node in graph}
        rec_stack = {node: False for node in graph}

        # Track the path and store the cycle nodes
        path = []

        # Perform DFS on each node that hasn't been visited yet
        for node in graph:
            if not visited[node]:
                if dfs(node, visited, rec_stack, path):
                    cycle_start = path[-1]  # Get the node where the cycle begins
                    cycle = []
                    for n in reversed(path):
                        cycle.append(n)
                        if n == cycle_start and len(cycle) > 1:
                            break
                    return True, cycle[::-1]  # return the cycle in correct order

        return False, []  # no cycle
class driver:
    def __init__(self, path, entry_function, stub_path) -> None:
        self.disasmbler = disasmbler.disasmbler(path, entry_function)
        if os.path.exists(stub_path):
            self.disasmbler.disasmstubs(stub_path)
        self.disasmbler.disasmsymbol()
        self.disasmbler.disasminvocation()  ##TODO @minghwu we also need to consider the cosrt_s_ from here as entry point.
        self.disasmbler.disasminst()
        self.disasmbler.disasminvotable()
        
        log("program entry:"+ str(self.disasmbler.entry_pc))
        log("program exit:"+ str(self.disasmbler.exit_pc))
        log("program stacksize"+ str(self.disasmbler.acquire_stack_size))
        self.register = register.register(self.disasmbler.acquire_stack_size)
        self.register.reg["pc"] = self.disasmbler.entry_pc
        self.execute = execute.execute(self.register, )
        self.parser = parser(self.disasmbler.symbol, 
                        self.disasmbler.inst, 
                        self.register,
                        self.execute,
                        self.disasmbler.entry_pc,
                        self.disasmbler.exit_pc,
                        self.disasmbler.invo_jmp_table,
                        self.disasmbler.thread_list,
                        self.disasmbler.function_call_address,
                        self.disasmbler.inst_address_to_symbol_name)
    
    def PowerOf2(self, N):
        # Calculate log2 of N
        a = int(math.log2(N))
    
        # If 2^a is equal to N, return N
        if 2**a == N:
            return a
        
        return a + 1

    def run(self):
        self.parser.stack_analyzer()
        
        logresult(self.parser.edge)
        logresult(self.parser.stackfunction)
        logresult(self.parser.stacklist)
        has_cycle, cycle_nodes = self.parser.find_cycle_directed(self.parser.edge)
        if has_cycle:
            logterminator(f"ERROR : Recursion detected. {cycle_nodes}")
        logresult(self.register.reg["max"])
        redzone = 128
        self.register.reg["max"] = self.register.reg["max"] - redzone
        logrust(self.PowerOf2(abs(self.register.reg["max"])))        

if __name__ == '__main__':
    
    if len(sys.argv) >=3:
        entry_function = sys.argv[2]
    else:
        entry_function = "__cosrt_upcall_entry"
    if len(sys.argv) >=2:
        path = sys.argv[1]
    else:
        path = "../../../system_binaries/cos_build-test/global.ping/tests.unit_pingpong.global.ping"
    if path.split(".")[-1] == "ping":
        stub_path = "../../../src/components/interface/" + "pong" + "/stubs/stubs.S"
    else:
        stub_path = "../../../src/components/interface/" + path.split(".")[-1] + "/stubs/stubs.S"
    driver = driver(path, entry_function, stub_path)
    driver.run()
    
    ## TODO: we need have case here, said it is not a good result. Like we have a alloc, or dynamic function pointer, or control flow function.
    ## know the reason why it is not reasonable.
    ## write a c program or assembly case, test case. make it to fail to make sure we could handle.
    ## return a function list or call graph of each function could get stack size and call instruction.
    ## 64 bytes , X86-64 redzone in ABI
    
    ## recursion, dynamice pointer, alloca. test case.