from analyze import TransactionReader, MessageCall

from create_all_accounts_db import DB

import glob

class AnalysisState:
    def __init__(self):
        self.target = {}

    def apply_tx_calls(self, tx_calls: [MessageCall]):
        for call in tx_calls:
            if call.receiver in self.target:
                self.target[call.receiver] += 1
            else:
                self.target[call.receiver] = 1

            if call.sender in self.target:
                self.target[call.sender] += 1
            else:
                self.target[call.sender] = 1

def main():
    analysis_state = AnalysisState()
    t = TransactionReader()
    start_block = 14000000
    end_block = 999999999999

    counter = 0
    done = False

    input_files = sorted(glob.glob("full-recent-traces/*.csv"))
    for input_file in input_files:
        print(input_file)
        source_data_file = open(input_file, 'r')
        
        # ignore the csv header
        for line in source_data_file:
            break

        count = 0

        # main analysis loop
        while True:
            tx_calls = t.ReadNextTransaction(source_data_file)
            if len(tx_calls) == 0:
                # result with 0 message calls is only returned
                # if the end of the dataset is reached
                break
            elif tx_calls[0].block_number > end_block:
                done = True
                break
            elif tx_calls[0].block_number < start_block:
                continue

            analysis_state.apply_tx_calls(tx_calls)

    db = DB.load("all_contracts_filtered2.db")
    db.create_addr_traces_count()
    for addr, count in analysis_state.target.items():
        db.add_addr_trace_no_commit(addr, count)
    db.connection.commit()

    import pdb; pdb.set_trace()
    foo = 'bar'

main()
