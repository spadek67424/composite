import sys
import disasmbler
import register
import execute
import jmp_class
import math
import networkx as nx
import os
import json
from debug import log, logresult, logrust, logerror, logterminator
from capstone.x86 import *
from capstone import *

class parser:
    def __init__(self, symbol, inst, register, execute, disassembler):
        self.symbol = symbol 
        self.inst = inst
        self.stacklist = []
        self.register = register
        self.execute = execute
        self.invo_jmp_table = disassembler.invo_jmp_table
        self.thread_list = disassembler.thread_list
        self.function_call_address = disassembler.function_call_address
        self.inst_address_to_symbol_name = disassembler.inst_address_to_symbol_name
        self.edge = nx.DiGraph()
        self.vertex = set()
        self.index = 0
        self.exit_pc = disassembler.exit_pc
        self.stackfunction = dict()
        self.stackfunction[self.symbol[disassembler.entry_pc]] = ((disassembler.entry_pc, -1))
        self.retjmppc = 0
        self.retjmpflag = 0
        self.retcallpc = []
        self.seenlist = [] ## handle the while loop jmp.
        self.JtypeClass = []

    def check_exe_virtual_return(self, address_list): # virtual ret.
        if self.index + 1 < len(address_list) and address_list[self.index + 1] in self.symbol.keys() : # have a virtual return address for some function does not have ret.
            self.execute.exe(-1)  
            if self.execute.retflag == 1:
                log("virtual return")
                return 1
        return 0
    
    def is_jtype_inst(self, inst):
        return (inst.id == X86_INS_CALL or
                inst.id == X86_INS_JMP or
                inst.id == X86_INS_JE or
                inst.id == X86_INS_JLE or
                inst.id == X86_INS_JGE or
                inst.id == X86_INS_JG or
                inst.id == X86_INS_JNE)
    
    def stack_analyzer(self, lookup_table = None):
        address_list = list(self.inst.keys())  ## a list for instruction address.
        address_list.append(-1) ## dummy value for last iteration.
        self.index = address_list.index(self.register.reg["pc"]) ## index for each instruction address.
        nextinstRip = list(self.inst.keys())
        nextinstRip.append(-1) ## dummy value for last iteration.
        self.register.updaterip(nextinstRip[self.index + 1 if self.index + 1 in nextinstRip else self.index]) ## catch the rip for memory instruction.
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
                    
            elif address_list[self.index] in self.invo_jmp_table:         ## looking up hardcode the invocation table, we jmp to target address.
                if self.inst[address_list[self.index]].id == X86_INS_CALL:
                    self.JtypeClass.append(jmp_class.JmpContext(self.index+1, self.index, self.register.reg["stack"], self.register.reg["rspbegin"], self.register.reg["rsp"]))
                if self.is_jtype_inst(self.inst[address_list[self.index]]):
                    self.JtypeClass.append(jmp_class.JmpContext(self.index+1, self.index, self.register.reg["stack"], self.register.reg["rspbegin"], self.register.reg["rsp"]))
                if self.invo_jmp_table[address_list[self.index]] in self.symbol:
                    self.JtypeClass.append(jmp_class.JmpContext(self.index+1, self.index, self.register.reg["stack"], self.register.reg["rspbegin"], self.register.reg["rsp"]))
                    if "__cosrt_c" in self.inst_address_to_symbol_name[self.invo_jmp_table[address_list[self.index]]]:
                        self.edge.add_edge(self.inst_address_to_symbol_name[address_list[self.index]], self.inst_address_to_symbol_name[self.invo_jmp_table[address_list[self.index]]])
                self.seenlist.append(address_list[self.index])
                self.index = address_list.index(self.invo_jmp_table[address_list[self.index]])
                self.register.reg["call_or_jmp"] = 0   ## clean the call/jmp indicator. 
                log("fastpace with hardcode invocation table.")

            elif address_list[self.index] == self.function_call_address:  ## looking up hardcode the thread address, and jmp to target address.
                self.JtypeClass.append(jmp_class.JmpContext(self.index + 1, self.index, self.register.reg["stack"], self.register.reg["rspbegin"], self.register.reg["rsp"]))
                for thread_function_address in self.thread_list:
                    self.JtypeClass.append(jmp_class.JmpContext(address_list.index(thread_function_address), self.index, self.register.reg["stack"], self.register.reg["rspbegin"], self.register.reg["rsp"]))
                    if thread_function_address in self.symbol and "__cosrt_c" in self.inst_address_to_symbol_name[thread_function_address]:
                        self.edge.add_edge(self.inst_address_to_symbol_name[address_list[self.index]], self.inst_address_to_symbol_name[thread_function_address])
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
                    if self.check_exe_virtual_return(address_list):
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
                        logterminator("ERROR : Dynamic Pointer Detected.")
                        if self.check_exe_virtual_return(address_list):
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
                        if self.symbol[self.register.reg["pc"]] in lookup_table and lookup_table[self.symbol[self.register.reg["pc"]]][1] != -1: ## DP fast path for call inst, means that it is already calculated.
                            self.register.reg["stack"] = self.register.reg["stack"] + lookup_table[self.symbol[self.register.reg["pc"]]][1]
                            self.index = self.index + 1
                        else:  ## slow path for call inst.
                            self.JtypeClass.append(jmp_class.JmpContext(self.index+1, self.index, self.register.reg["stack"], self.register.reg["rspbegin"], self.register.reg["rsp"]))
                            self.seenlist.append(address_list[self.index])
                            self.stackfunction[self.symbol[self.register.reg["pc"]]] = ((self.register.reg["pc"], -1))
                            if self.register.reg["pc"] in self.symbol and  "__cosrt_c" in self.inst_address_to_symbol_name[self.register.reg["pc"]]:
                                self.edge.add_edge(self.inst_address_to_symbol_name[address_list[self.index]], self.inst_address_to_symbol_name[self.register.reg["pc"]])
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
                        logterminator("ERROR : Dynamic Pointer Detected.")
                        if self.check_exe_virtual_return(address_list):
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
                        if self.register.reg["pc"] in self.symbol and "__cosrt_c" in self.inst_address_to_symbol_name[self.register.reg["pc"]]:
                            self.edge.add_edge(self.inst_address_to_symbol_name[address_list[self.index]], self.inst_address_to_symbol_name[self.register.reg["pc"]])
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
    def find_all_cycles_directed(self, edges):
        # Step 1: Build adjacency list
        graph = {}
        for from_node, to_node in edges:
            if from_node not in graph:
                graph[from_node] = []
            graph[from_node].append(to_node)
            if to_node not in graph:
                graph[to_node] = []

        # Step 2: DFS to find cycles
        def dfs(node, visited, rec_stack, path):
            visited[node] = True
            rec_stack[node] = True
            path.append(node)

            for neighbor in graph[node]:
                if not visited[neighbor]:  # Continue DFS
                    dfs(neighbor, visited, rec_stack, path)
                elif rec_stack[neighbor]:  # Cycle detected
                    # Extract the cycle
                    cycle_start_index = path.index(neighbor)
                    cycle = tuple(path[cycle_start_index:])  # Convert to tuple to make it hashable
                    # Normalize the cycle to avoid duplicates (start from smallest node)
                    min_index = cycle.index(min(cycle))
                    cycle = cycle[min_index:] + cycle[:min_index]  # Rotate to smallest node first
                    cycles.add(tuple(cycle))  # Add normalized cycle to set

            # Backtrack
            rec_stack[node] = False
            path.pop()

        # Initialize
        visited = {node: False for node in graph}
        rec_stack = {node: False for node in graph}
        cycles = set()  # Store unique cycles

        # Perform DFS for all nodes
        for node in graph:
            if not visited[node]:
                dfs(node, visited, rec_stack, [])

        # Return all cycles as a list
        return [list(cycle) for cycle in cycles]
class driver:
    def __init__(self, path, entry_function, stub_paths) -> None:
        self.path = path
        self.entry_function = entry_function
        self.stub_paths = stub_paths
        self.disasmbler = disasmbler.disasmbler(self.path, self.entry_function)
        self.disasmbler.disasmstubs(self.stub_paths)
        self.disasmbler.disasmsymbol()
        self.disasmbler.disasminvocation()
        self.disasmbler.disasminst()
        self.disasmbler.disasminvotable()
        self.edge = nx.DiGraph()
        self.stackfunction = dict()
        log("program entry:"+ str(self.disasmbler.entry_pc))
        log("program exit:"+ str(self.disasmbler.exit_pc))
        log("program stacksize"+ str(self.disasmbler.acquire_stack_size))
        self.register = register.register(self.disasmbler.acquire_stack_size)
        self.register.reg["pc"] = self.disasmbler.entry_pc
        self.execute = execute.execute(self.register)
        self.parser = parser(self.disasmbler.symbol, 
                             self.disasmbler.inst, 
                             self.register,
                             self.execute,
                             self.disasmbler)
    def reset(self, entry_function):
        self.entry_function = entry_function
        self.disasmbler = disasmbler.disasmbler(self.path, self.entry_function)
        self.disasmbler.disasmstubs(self.stub_paths)
        self.disasmbler.disasmsymbol()
        self.disasmbler.disasminvocation()
        self.disasmbler.disasminst()
        self.disasmbler.disasminvotable()
        
        log("program entry:"+ str(self.disasmbler.entry_pc))
        log("program exit:"+ str(self.disasmbler.exit_pc))
        log("program stacksize"+ str(self.disasmbler.acquire_stack_size))
        self.register = register.register(self.disasmbler.acquire_stack_size)
        self.register.reg["pc"] = self.disasmbler.entry_pc
        self.execute = execute.execute(self.register)
        self.parser = parser(self.disasmbler.symbol, 
                             self.disasmbler.inst, 
                             self.register,
                             self.execute,
                             self.disasmbler)
    
    def PowerOf2(self, N):
        # Calculate log2 of N
        a = int(math.log2(N))
        
        # If 2^a is equal to N, return N
        if 2**a == N:
            return a
        return a + 1
    def round_up_to_power_of_2(self, n):
        if n <= 1:
            return 1
        return 2 ** math.ceil(math.log2(n))
    def merge_two_dicts(self, dict1, dict2):
        for key in dict1:
            if key in dict2 and dict1[key][1] == -1:  # Overwrite condition
                self.stackfunction[key] = dict2[key]
            else:  # Keep the original value
                self.stackfunction[key] = dict1[key]

        # Add keys in dict2 that are not in dict1
        for key in dict2:
            if key not in dict1:
                self.stackfunction[key] = dict2[key]
        return self.stackfunction
    def run(self):
        self.parser.stack_analyzer(self.stackfunction)
        try:
            cycles = list(nx.simple_cycles(self.parser.edge))
            logterminator("ERROR : Recursion detected.")
        except:
            pass
        redzone = 128
        self.register.reg["max"] = self.register.reg["max"] - redzone
        logresult(self.register.reg["max"])
        logresult(self.disasmbler.entry_pc)
        self.edge.update(self.parser.edge)  ## here could be faster if we just need the dependency.
        self.parser.stackfunction[self.entry_function] = ((self.disasmbler.entry_pc, self.register.reg["max"], self.parser.edge)) 
        print(self.parser.edge.nodes)
        print(self.parser.edge.edges)
        self.stackfunction = self.stackfunction | self.parser.stackfunction # Merges the two dicts
        # keepgoing = 1
        # while(keepgoing):
        #     for key, value in self.stackfunction.items():
        #         if value[1] == -1:  # Check if the second element is -1
        #             self.reset(key)
        #             self.parser.stack_analyzer(self.stackfunction)
        #             try:
        #                 cycles = list(nx.simple_cycles(self.parser.edge))
        #                 if len(cycles) > 0:
        #                     logterminator("ERROR : Recursion detected.")
        #                     logterminator(cycles)
        #             except:
        #                 pass
        #             self.edge.update(self.parser.edge)
        #             self.parser.stackfunction[key] = ((self.disasmbler.entry_pc, self.register.reg["max"], self.parser.edge))
        #             self.stackfunction = self.merge_two_dicts(self.stackfunction, self.parser.stackfunction) # Merges the two dicts
        #             keepgoing = 1
        #             break
        #         else:
        #             keepgoing = 0
        #     logresult("key = " + str(key))
        #     logresult(self.edge.edges)
        print("final")
        print(self.edge.nodes)
        print(self.edge.edges)
        print(self.stackfunction)
        # Convert all DiGraph objects in your data
        return self.stackfunction

# Function to convert a DiGraph to a JSON-serializable format
def convert_digraph_to_json_compatible(data, entry_function):
    result = dict()
    for key in entry_function:
        output = set()
        value = data[key]
        # If the third element of the tuple is a DiGraph, convert it
        if isinstance(value[2], nx.DiGraph):
            # Get the node-link representation of the graph
            node_link_data = nx.node_link_data(value[2])
            # Iterate over the links (edges) in the node-link data
            for link in node_link_data['links']:
                if "cosrt_c" in link['source']:
                    output.add(link['source'])
                if "cosrt_c" in link['target']:
                    output.add(link['target'])
            # Replace the third element of the tuple with the output set
            if len(output) > 0 :
                result[key] = {"address" : hex(value[0]), "usize" : abs(value[1]), "dependencies" : list(output)}
            else:
                result[key] = {"address" : hex(value[0]), "usize" : abs(value[1])}
    return result
if __name__ == '__main__':
    if len(sys.argv) >=3:
        entry_function = sys.argv[2]
    else:
        entry_function = list(["__cosrt_upcall_entry", "__cosrt_extern_pong_args"])
    if len(sys.argv) >=2:
        path = sys.argv[1]
    else:
        path = "/home/minghwu/work/composite/system_binaries/cos_build-pingpong/global.ping/tests.unit_pingpong.global.ping"
        
    # Directory to search
    directory = "/home/minghwu/work/composite/src/components/interface/"
    stub_name = "stubs.S"
    stub_paths = []
    # Traverse the directory
    for root, dirs, files in os.walk(directory):
        if stub_name in files:
            stub_paths.append(os.path.join(root, stub_name))
    graph = dict()
    for i in entry_function:
        driver_main = driver(path, i, stub_paths)
        graph = driver_main.merge_two_dicts(graph, driver_main.run())
        del driver_main
    converted_data = convert_digraph_to_json_compatible(graph, entry_function)
    log("Data has been written to 'output.json'")
    logrust(json.dumps(converted_data, indent=4))