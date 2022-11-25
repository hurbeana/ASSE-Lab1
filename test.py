import angr
stash = {"found":[]}
def checkOverflow(binary_name):

    p = angr.Project(binary_name, load_options={"auto_load_libs": False})
    handle_connection = p.loader.main_object.get_symbol(
        'handle_connection')
    state = p.factory.entry_state(addr=handle_connection.rebased_addr)
    state.libc.buf_symbolic_bytes = 0x70
    simgr = p.factory.simgr(state, save_unconstrained=True)
    simgr.explore(step_func=overflow_filter)
    
    
def overflow_filter(simgr):
    for state in simgr.unconstrained:
        print(state)
        if exploitable(state):
            print("find state",state)
            simgr.stashes['found'].append(state)
    return simgr
        
def exploitable(state):
    for i in range(state.arch.bits):
        if not state.solver.symbolic(state.regs.pc[i]):
            return False
    return True
binary_name = './bof1'
checkOverflow(binary_name)