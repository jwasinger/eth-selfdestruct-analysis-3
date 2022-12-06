def calc_offset_of_next_op(cur_idx: int, cur_op: str) -> int:
    cur_op_int = int(cur_op, 16)
    if cur_op_int <= 0x7f and cur_op_int >= 0x60:
        immediate_size = ((cur_op_int + 1) - 0x60) * 2
        res = cur_idx + immediate_size + 2
        # print("immediate size is {}".format(immediate_size))
        return res
    else:
        return cur_idx + 2

def contains_selfdestruct(bytecode: str):
    cur_idx = 0
    cur_op = None

    while cur_idx < len(bytecode):
        cur_op = bytecode[cur_idx:cur_idx + 2]
        if cur_op == 'ff':
            # cur op is selfdestruct
            return True

        cur_idx = calc_offset_of_next_op(cur_idx, cur_op)

    return False

SELFDESTRUCT_OP = 'ff'
CREATE2_OP = 'f5'

def contains_selfdestruct_or_create2(bytecode: str):
    cur_idx = 0
    cur_op = None

    has_selfdestruct, has_create2 = False, False

    while cur_idx < len(bytecode):
        cur_op = bytecode[cur_idx:cur_idx + 2]
        if cur_op == SELFDESTRUCT_OP:
            # cur op is selfdestruct
            has_selfdestruct = True
        elif cur_op == CREATE2_OP:
            has_create2 = True
        elif bytecode[cur_idx:cur_idx + 2] == '00a2':
            import pdb; pdb.set_trace()
            foo = 'bar'

        cur_idx = calc_offset_of_next_op(cur_idx, cur_op)

    return has_selfdestruct, has_create2

def is_push(opcode: str):
    assert len(opcode) == 2, print(opcode)
    val = int(opcode, 16)
    if val >= 0x60 and val <= 0x7f:
        return True
    return False

def calc_push_immediate_size(opcode: str):
    assert len(opcode) == 2
    val = int(opcode, 16)
    if val < 0x60 or val > 0x7f:
        raise Exception("not a push opcode")
    return val - 0x5f

OP_CREATE       = 'f0'
OP_CREATE2      = 'f5'
OP_SELFDESTRUCT = 'ff'

# return whether a bytecode contained a create, create2, whether the bytecode contained a likely-reachable selfdestruct
def analyze(bytecode: str) -> (bool, bool, bool):
    assert len(bytecode) % 2 == 0

    is_selfdestructable = False
    has_create = False
    has_create2 = False

    cur_op = None
    prev_op = None
    cur_idx = 0

    while cur_idx < len(bytecode):
        prev_op = cur_op
        cur_op = bytecode[cur_idx:cur_idx + 2]
        if is_push(cur_op):
            immediate_size = calc_push_immediate_size(cur_op) * 2
            cur_idx += immediate_size
        elif cur_op == OP_CREATE:
            has_create = True
        elif cur_op == OP_CREATE2:
            has_create2 = True
        elif cur_op == OP_SELFDESTRUCT:
            is_selfdestructable = True
        elif cur_op == 'a2' and prev_op != None and prev_op == '00':
            # heuristic to catch the start of a solidity metadata section.  TODO make this better
            break

        cur_idx += 2

    return has_create, has_create2, is_selfdestructable
