import itertools
import functools
import glob

total_created = 0
total_selfdestructed = 0

def sort_tx_calls(calls):
    def sort_fn(x, y) -> int:
        for t1, t2 in itertools.zip_longest(x.trace_id, y.trace_id):
            if t2 == None:
                return 1
            elif t1 == None:
                return -1

            if t1 > t2:
                return 1
            elif t1 < t2:
                return -1
        return 0

    return sorted(calls, key=functools.cmp_to_key(sort_fn))

def parse_trace_id(s: str):
    parts = s.split('_')[2:]
    parts = [part for part in parts if part != '']
    parts = [0] + [int(part) for part in parts]

    if len(parts) == 0:
        parts = [0]
    return parts

class MessageCall():
    def __init__(self, block_number, tx_hash, tx_index, trace_id, sender, receiver, typ, status, call_type, value):
        self.block_number = block_number
        self.tx_hash = tx_hash
        self.tx_index = tx_index
        self.trace_id = trace_id
        self.sender = sender
        self.receiver = receiver
        self.type = typ
        self.status = status
        self.call_type=call_type
        self.call_depth = len(trace_id) - 1
        self.parent_call = None
        self.value = value

    @staticmethod
    def FromCSVLine(s: str):
        parts = s.strip('\n').split(',')

        if len(parts) != 11:
            raise Exception("wrong length")

        typ = parts[7]
        if typ == 'reward':
            return None # we don't care about block rewards traces (right now)
        block_number = int(parts[3])
        tx_hash = parts[1]
        tx_index = int(parts[4])
        trace_id = parse_trace_id(parts[2])
        sender = parts[5]
        receiver = parts[6]

        status = int(parts[9])
        calltype = parts[8]
        value = parts[10]

        return MessageCall(block_number, tx_hash, tx_index, trace_id, sender, receiver, typ, status, calltype, value)

    def ToCSVLine(self):
        return "{},{},{},{},{},{},{}".format(self.tx_hash, self.tx_index, self.sender, self.sender, self.trace_id, self.call_type, self.type, self.status)

def find_direct_parent(call, tx_calls) -> MessageCall:
    return None
    for c in reversed(tx_calls):
        if c.call_depth == call.call_depth - 1 and c.trace_id == call.trace_id[:-1]:
            return c

    return None

class TransactionReader:
    def __init__(self):
        self.last_trace = None

    # TODO this is broken in the case where a transaction straddles two files
    def ReadNextTransaction(self, query_rows, link_txs=True) -> [MessageCall]:
        tx_traces = []
        first_trace = None
        if self.last_trace != None:
            first_trace = self.last_trace
            tx_traces.append(first_trace)
            self.last_trace = None

        for idx, row in enumerate(query_rows):
            row_trace = MessageCall.FromCSVLine(row)
            if not row_trace: # ignore block rewards traces
                continue

            if first_trace == None:
                first_trace = row_trace
                tx_traces.append(first_trace)
                continue
                
            if first_trace.tx_hash != row_trace.tx_hash:
                self.last_trace = row_trace
                break

            if link_txs:
                row_trace.parent_call = find_direct_parent(row_trace, tx_traces)
            tx_traces.append(row_trace)

        if len(tx_traces) > 1:
            tx_traces = sort_tx_calls(tx_traces)

        return tx_traces

class AnalysisState:
    def __init__(self, start_block):
        self.start_block = start_block

        self.ephemerals = {}
        self.reincarnations = {}
        self.selfdestructed = set()
        self.created = set()

        # map of contract address -> address of contract that created it
        self.creators = {}

        # map of contract address -> (creation_tx_hash, creation_block_number)
        self.created_info = {}

    def ApplyTransactionCalls(self, tx_calls: [MessageCall]):
        global total_created
        global total_selfdestructed

        tx_created = {}
        tx_selfdestructed = set()
        tx_ephemerals = set() 

        for call in tx_calls:
            if call.status == 0:
                continue
            if call.type == 'create':
                total_created += 1
                if call.receiver in tx_created:
                    raise Exception("the same contract cannot be created twice during the same transaction")
                tx_created[call.receiver] = (call.sender, call.block_number, call.tx_hash)
                if not call.receiver in self.creators:
                    self.creators[call.receiver] = call.sender
            elif call.type == 'suicide': # call is selfdestruct
                total_selfdestructed += 1
                if not call.sender in tx_selfdestructed and not call.sender in tx_ephemerals:
                    if call.sender in tx_created:
                        tx_ephemerals.add(call.sender)
                        del tx_created[call.sender]
                    else:
                        tx_selfdestructed.add(call.sender)

                if call.sender in tx_ephemerals:
                    if not call.sender in self.creators:
                        raise Exception("ephemeral address should have been in created map")
            elif call.type == 'call':
                if call.call_type == 'delegatecall':
                    pass
                elif call.call_type == 'callcode':
                    pass
                else:
                    raise Exception("unexpected call type {}".format(call.call_type))
            elif call.type == None:
                raise Exception("unexpected trace type {}".format(call.type))

        for address in tx_created:
            if address in self.created:
                raise Exception("address created twice without being deleted: {0}".format(address))
            if address in self.selfdestructed:
                self.selfdestructed.remove(address)
                if self.start_block <= tx_calls[0].block_number:
                    if address in self.reincarnations:
                        self.reincarnations[address] += 1
                    else: 
                        self.reincarnations[address] = 1

            if address in self.created:
                raise Exception("shit 1")
            if address in self.created_info:
                raise Exception("shit 2")

            self.created.add(address)
            self.created_info[address] = (tx_created[address][0], tx_created[address][1], tx_created[address][2])

        for address in tx_selfdestructed:
            if address in self.selfdestructed:
                raise Exception("address selfdestructed twice without being resurected in-between: {0}".format(address))

            if address in self.created:
                self.created.remove(address)
                del self.created_info[address]
            else:
                raise Exception("fuck")

            self.selfdestructed.add(address)

        if self.start_block <= tx_calls[0].block_number:
            for address in tx_ephemerals:
                if not address in self.ephemerals:
                    self.ephemerals[address] = 1
                else:
                    self.ephemerals[address] += 1

progress_str = "_.."
def advance_progress():
    global progress_str

    if progress_str == "_..":
        progress_str = "._."
    elif progress_str == "._.":
        progress_str = ".._"
    elif progress_str == ".._":
        progress_str = "_.."

    return progress_str

def do_analysis(start_block, end_block):
    counter = 0
    done = False

    input_files = sorted(glob.glob("data-traces/*.csv"))

    analysis_state = AnalysisState(start_block)

    t = TransactionReader()

    for input_file in input_files:
        source_data_file = open(input_file, 'r')
        for line in source_data_file:
            break

        print("analyzing {}".format(input_file))

        while True:
            tx_calls = t.ReadNextTransaction(source_data_file)
            if len(tx_calls) == 0:
                break

            if tx_calls[0].block_number > end_block:
                done = True
                break

            analysis_state.ApplyTransactionCalls(tx_calls)

            counter += 1
            if counter % 1000 == 0:
                print(advance_progress(), end="\r")

        if done:
            break

    return analysis_state

def save_analysis(analysis_result: AnalysisState, creators_of_redeployed_file_path: str, redeployed_file_path: str, ephemerals_creators_path: str, ephemerals_addrs_path: str):
    ephemeral_creators = {}
    ephemeral_creators_which_reuse = set()

    for address, num_ephemerals in analysis_result.ephemerals.items():
        if not address in analysis_result.creators:
            raise Exception("missing creator for ephemeral address {}".format(address))

        creator = analysis_result.creators[address]
        if not creator in ephemeral_creators:
            ephemeral_creators[creator] = num_ephemerals
        else:
            ephemeral_creators[creator] += num_ephemerals

        if num_ephemerals > 1:
            ephemeral_creators_which_reuse.add(creator)

    reincarnated_creators = {}
    for address, num_incarnations in analysis_result.reincarnations.items():
        creator = ''
        if not address in analysis_result.creators:
            raise Exception("address should be in creators")

        if address in analysis_result.ephemerals:
            import pdb; pdb.set_trace()
            foo = 'bar'

        creator = analysis_result.creators[address]
        if not creator in reincarnated_creators:
            reincarnated_creators[creator] = 1
        else:
            reincarnated_creators[creator] += 1

    import pdb; pdb.set_trace()
    with open(ephemerals_creators_path, "w") as f:
        f.write("creator contract address, number of ephemeral contracts created\n")

        for creator, num_ephemerals in sorted(ephemeral_creators.items()):
            f.write("{}, {}\n".format(creator, num_ephemerals))

    with open(creators_of_redeployed_file_path, "w") as f:
        f.write("creator contract address, number of child contracts that were redeployed\n")

        for creator, num_redeployed in sorted(reincarnated_creators.items()):
            f.write("{}, {}\n".format(creator, num_redeployed))

    with open(redeployed_file_path, 'w') as f:
        f.write("redeployed address, number of redeployments\n")

        for address, num_incarnations in sorted(analysis_result.reincarnations.items()):
            f.write("{}, {}\n".format(address, num_incarnations))

    with open(ephemerals_addrs_path, 'w') as f:
        f.write("contract address\n")

        for item in sorted(analysis_result.ephemerals.items(), key=lambda x: x[0]):
            f.write("{},{}\n".format(item[0], item[1]))

def analysis1():
    analysis_genesis_to_x = do_analysis(0, 999999999999999999999999)
    import pdb; pdb.set_trace()
    with open('created_info.csv', 'w') as f:
        for addr, info in sorted(analysis_genesis_to_x.created_info.items(), key = lambda x: int(x[0], 16)):
            f.write("{},{},{},{}\n".format(addr, info[0], info[1], info[2]))
    save_analysis(analysis_genesis_to_x, "analysis-results/genesis-to-12799316/creators-of-redeployed-addrs.csv", "analysis-results/genesis-to-12799316/redeployed-addrs.csv", "analysis-results/genesis-to-12799316/creators-of-ephemeral-contracts.csv", "analysis-results/genesis-to-12799316/ephemeral-addrs.csv")

def analysis2():
    london_to_present = do_analysis(12965000, 999999999999999999999999)
    save_analysis(london_to_present, "analysis-results/london-to-present/creators-of-redeployed-addrs.csv", "analysis-results/london-to-present/redeployed-addrs.csv", "analysis-results/london-to-present/creators-of-ephemeral-contracts.csv", "analysis-results/london-to-present/ephemeral-addrs.csv")

if __name__ == "__main__":
    analysis1()
