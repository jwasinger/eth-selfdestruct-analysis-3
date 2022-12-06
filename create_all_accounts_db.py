import sqlite3
import os, glob

from eth_utils import keccak as keccak256
import evm_parser

class DBCodeHash():
    def __init__(self, code_hash='NULL', bytecode='NULL', has_create='NULL', has_create2='NULL', is_selfdestructable='NULL'):
        self.code_hash = code_hash
        self.bytecode = bytecode
        self.has_create = has_create
        self.has_create2 = has_create2
        self.is_selfdestructable = is_selfdestructable

class Contract():
    def __init__(self, address='NULL', block_number='NULL', creation_tx_hash = 'NULL', code_hash = 'NULL', creator = 'NULL', creation_tx = 'NULL'):
        self.address = address
        self.block_number = block_number
        self.creation_tx_hash = creation_tx_hash
        self.code_hash = code_hash
        self.creator = creator

class DB():
    def __init__(self):
        pass

    @staticmethod
    def load(db_name):
        already_exists = False
        if not os.path.exists(db_name):
            raise Exception("db doesn't exist: {}".format(db_name))

        db = DB()
        db.connection = sqlite3.connect(db_name)
        db.cursor = db.connection.cursor()

        return db

    @staticmethod
    def new(name):
        if os.path.exists(name):
            os.remove(name)

        db = DB()
        db.connection = sqlite3.connect(name)
        db.cursor = db.connection.cursor()
        db.create_contracts_table()
        db.create_code_hashes_table()
        return db

    @staticmethod
    def load_or_new(db_name):
        already_exists = False
        if os.path.exists(db_name):
            already_exists = True

        db = DB()
        db.connection = sqlite3.connect(db_name)
        db.cursor = db.connection.cursor()

        if not already_exists:
            print("creating new db")
            db.create_code_hashes_table()
            db.create_contracts_ta()
        else:
            print("opened existing db")

        return db

    def create_contracts_table(self):
        self.cursor.execute("CREATE TABLE contracts (address TEXT NOT NULL, block_number INTEGER, code_hash TEXT, creator TEXT, creation_tx_hash TEXT, FOREIGN KEY(code_hash) REFERENCES codeHashes(hash))")
        self.connection.commit()

    def create_code_hashes_table(self):
        self.cursor.execute('CREATE TABLE codeHashes (code_hash TEXT NOT NULL PRIMARY KEY, bytecode TEXT NOT NULL, isSelfdestructable BOOL NOT NULL, hasCreateOp BOOL NOT NULL, hasCreate2Op BOOL NOT NULL)')
        self.connection.commit()

    def containsCodeHash(codeHash: str, self):
        self.cursor.execute('SELECT EXISTS(SELECT 1 FROM codeHashes WHERE hash="{}");'.format(codeHash))
        self.connection.commit()

    def add_contract_no_commit(self, contract: Contract):
        self.cursor.execute("INSERT INTO contracts VALUES ('{}', {}, '{}', '{}', '{}')".format(contract.address, contract.block_number, contract.code_hash, contract.creator, contract.creation_tx_hash))

    def add_code_hash_no_commit(self, code_hash_entry):
        self.cursor.execute("INSERT INTO codeHashes VALUES ('{}', '{}', {}, {}, {})".format(
            code_hash_entry.code_hash,
            code_hash_entry.bytecode,
            code_hash_entry.is_selfdestructable,
            code_hash_entry.has_create,
            code_hash_entry.has_create2))

    def add_contract(self, contract: Contract):
        self.add_contract_no_commit(contract)
        self.connection.commit()

    def get_contract(self, addr):
        pass
    def get_codehashes_count(self):
        cursor = self.connection.cursor()
        return list(cursor.execute('SELECT COUNT(*) FROM codeHashes'))[0][0]

    def get_code_hash(self, code_hash):
        cursor = self.connection.cursor()
        row = cursor.execute("SELECT * from codeHashes where code_hash='{}'".format(code_hash)).fetchone()
        return DBCodeHash(code_hash=row[0], bytecode=row[1], is_selfdestructable = row[2], has_create = row[3], has_create2 = row[4])

    def drop_codehashes(self):
        self.cursor.execute('DROP TABLE codeHashes')

    def iterate_code_hashes(self):
        cursor = self.connection.cursor()
        for row in self.cursor.execute('SELECT * FROM codeHashes ORDER BY code_hash'):
            yield DBCodeHash(code_hash=row[0], bytecode=row[1], is_selfdestructable = row[2], has_create = row[3], has_create2 = row[4])
        pass

    def get_contract(self, addr):
        cursor = self.connection.cursor()
        row = cursor.execute("SELECT * from contracts where address='{}'".format(addr))
        address = row[0]
        block_number = row[1]
        code_hash = row[2]
        creator = row[3]
        creation_tx_hash = row[4]

        contract = Contract(address = address, block_number = block_number, code_hash = code_hash, creator = creator, creation_tx_hash = creation_tx_hash)
        return contract

    def iterate_contracts(self):
        for row in self.cursor.execute('SELECT * FROM contracts order by address'):
            address = row[0]
            block_number = row[1]
            code_hash = row[2]
            creator = row[3]
            creation_tx_hash = row[4]

            contract = Contract(address = address, block_number = block_number, code_hash = code_hash, creator = creator, creation_tx_hash = creation_tx_hash)
            yield contract

    def iterate_contracts_by_code_hash(self):
        for row in self.cursor.execute('SELECT * FROM contracts order by code_hash'):
            address = row[0]
            block_number = row[1]
            code_hash = row[2]
            creator = row[3]
            creation_tx_hash = row[4]

            contract = Contract(address = address, block_number = block_number, code_hash = code_hash, creator = creator, creation_tx_hash = creation_tx_hash)
            yield contract

    def create_addr_traces_count(self):
        self.cursor.execute('CREATE TABLE address_traces (address TEXT NOT NULL, count INTEGER NOT NULL)')

    def add_addr_trace_no_commit(self, address, trace_count):
        self.cursor.execute("INSERT INTO address_traces VALUES ('{}', {})".format(address, trace_count))

    def create_ephemerals_creators(self):
        self.cursor.execute('CREATE TABLE ephemerals_creators (address TEXT NOT NULL, count INTEGER NOT NULL)')

    def add_ephemeral_creator_no_commit(self, address, ephemeral_count):
        self.cursor.execute("INSERT INTO ephemerals_creators VALUES ('{}', {})".format(address, ephemeral_count))

    def create_accounts_balances(self):
        self.cursor.execute('CREATE TABLE accounts_balances (address TEXT NOT NULL, balance INTEGER NOT NULL)')

    def add_account_balance_no_commit(self, addr, balance):
        self.cursor.execute("INSERT INTO accounts_balances VALUES ('{}', {})".format(addr, balance))

    def create_prev_reinited(self):
        self.cursor.execute("CREATE TABLE prev_reinited (address TEXT NOT NULL, count INTEGER NOT NULL)")

    def add_prev_reinited_no_commit(self, addr, count):
        self.cursor.execute("INSERT INTO prev_reinited VALUES ('{}', {})".format(addr, count))

def main():
    db = DB.new("all_contracts.db")
    contracts = {}
    # lookup of code-hash -> is-selfdestructable
    code_hashes = {}

    count = 0
    for csvfile in glob.glob("all-contracts/*.csv"):
        with open(csvfile) as f:
            for line in f: # skip the header
                break

            for line in f:

                parts = line.split(',')
                address = parts[0]
                bytecode = parts[1]
                block_num = parts[2]
                block_hash = parts[3]
                code_hash = keccak256(hexstr=bytecode[2:]).hex()
                is_selfdestructable = False
                has_create2 = False

                code_hash_entry = None

                if code_hash in code_hashes:
                    code_hash_entry = code_hashes[code_hash]
                else:
                    has_create, has_create2, is_selfdestructable = evm_parser.analyze(bytecode[2:])
                    code_hash_entry = DBCodeHash(code_hash=code_hash, bytecode=bytecode, has_create=has_create, has_create2=has_create2, is_selfdestructable=is_selfdestructable)
                    db.add_code_hash_no_commit(code_hash_entry)
                    code_hashes[code_hash] = code_hash_entry

                if len(code_hash) != 64:
                    import pdb; pdb.set_trace()
                    code_hash = '0' + code_hash
                contract = Contract(address = address, code_hash = code_hash_entry.code_hash, block_number=block_num)

                contracts[address] = contract
                db.add_contract_no_commit(contract)
        db.connection.commit()
        print("added file")

def update_codehashes():
    # TODO: 
    all_contracts_db = DB.load('all_contracts.db')

    code_hashes = []
    prev_count = all_contracts_db.get_codehashes_count()

    counter1 = 0
    # iterate all codehash entries in order, analyzing each of the bytecodes
    for code_hash_entry in all_contracts_db.iterate_codehashes():
        import pdb; pdb.set_trace()
        code_hash_entry.has_create, code_hash_entry.has_create2, code_hash_entry.is_selfdestructable = evm_parser.analyze(code_hash_entry.bytecode)
        code_hashes.append(code_hash_entry)
        counter1 += 1
        if counter1 % 10000 == 0:
            break

    # drop old codehashes table
    all_contracts_db.drop_codehashes()

    all_contracts_db.create_code_hashes_table_2()
    # add new codehashes table with updated entries
    for code_hash_entry in code_hashes:
        import pdb; pdb.set_trace()
        all_contracts_db.add_code_hash_no_commit(code_hash_entry)

    all_contracts_db.connection.commit()

# filter contracts to only include the latest incarnation
def ingest_all_contracts_filter():
    all_contracts_db = DB.load('all_contracts.db')
    all_contracts_filtered_db = DB.new('all_contracts_filtered.db')

    last_contract = None

    # map of code_hash -> is_selfdestructable
    code_hashes = {}

    print("start filter stage")

    alive_addresses = []

    counter = 0
    cur_address_incarnations = []
    greatest = None

    last_contract = None

    for contract in all_contracts_db.iterate_contracts():
        if last_contract == None:
            greatest = contract
            last_contract = contract
        elif contract.address != last_contract.address:
            all_contracts_filtered_db.add_contract_no_commit(greatest)

            greatest = contract
            last_contract = contract
        else:
            if contract.block_number > greatest.block_number:
                greatest = contract
            last_contract = contract

        counter += 1
        if counter % 10000 == 0:
            print(counter)

    all_contracts_filtered_db.connection.commit()
    for code_hash_entry in all_contracts_db.iterate_code_hashes():
        all_contracts_filtered_db.add_code_hash_no_commit(code_hash_entry)

    all_contracts_filtered_db.connection.commit()
    # TODO count last contract too

def filter_for_alive_selfdestructable():
    all_contracts_filtered_db = DB.load('all_contracts_filtered.db')

    # query for selfdestructable contracts from 'contracts_filtered' ordering by address
    # query for alive contracts ordering by address

    with open('sorted_created_addrs.txt', 'r') as f:
        all_contracts_iter = all_contracts_filtered_db.iterate_contracts()
        created_contracts_iter = f

        all_contract = next(all_contracts_iter)
        created_contract = next(created_contracts_iter)

        count = 0
        while True:
            if int(created_contract, 16) < int(all_contract.address, 16):
                # this means that there is a 'created' address that wasn't present in all_contracts
                # TODO note this address and move on
                created_contract = next(created_contracts_iter)
            elif int(created_contract, 16) > int(all_contract.address, 16):
                # there was a selfdestructed address
                all_contract = next(all_contracts_iter)
            else:
                # found a contract that exists
                code_hash_entry = all_contracts_filtered_db.get_code_hash(all_contract.code_hash)
                if code_hash_entry.is_selfdestructable:
                    import pdb; pdb.set_trace()
                    print(all_contract.address)
                created_contract = next(created_contracts_iter)
                all_contract = next(all_contracts_iter)

def fill_in_creator_tx_hash():
    db = DB.load('all_contracts_filtered.db')
    new_db = DB.new('all_contracts_filtered2.db')
    updated_contracts = []

    with open('created_info.csv') as f:
        contract_iterator = db.iterate_contracts()
        created_info_iter = f

        cur_contract = next(contract_iterator)
        created_info = next(created_info_iter)
        created_info = created_info.strip('\n').replace(' ', '').split(',')
        created_info_addr = created_info[0]
        created_info_sender = created_info[1]
        created_info_block_num = created_info[2]
        created_info_tx_hash = created_info[3]

        while True:
            if int(created_info_addr, 16) < int(cur_contract.address, 16):
                # the contract that was at created_info_addr was deleted
                # TODO advance created_info_iterator but not cur_contract
                created_info_addr = None
                created_info_block_num = None
                created_info_sender = None
                created_info_tx_hash = None
                try: 
                    created_info = next(created_info_iter)
                    created_info = created_info.strip('\n').replace(' ', '').split(',')
                    created_info_addr = created_info[0]
                    created_info_sender = created_info[1]
                    created_info_block_num = created_info[2]
                    created_info_tx_hash = created_info[3]
                except StopIteration as e: # TODO assert exception type
                    import pdb; pdb.set_trace()
                    break
            elif int(created_info_addr, 16) > int(cur_contract.address, 16): 
                # for some reason an address was in the set of all contracts
                # but doesn't have a created_info entry.  fail hard

                # TODO raise exception here when we are crunching the full dataset
                # raise Exception("dataset mismatch")

                try:
                    cur_contract = next(contract_iterator)
                except StopIteration as e:
                    import pdb; pdb.set_trace()
                    break
            else:
                cur_contract.creation_tx_hash = created_info_tx_hash
                cur_contract.creator = created_info_sender
                cur_contract.block_number = created_info_block_num
                updated_contracts.append(cur_contract)

                try: 
                    created_info = next(created_info_iter)
                    created_info = created_info.strip('\n').replace(' ', '').split(',')
                    created_info_addr = created_info[0]
                    created_info_sender = created_info[1]
                    created_info_block_num = created_info[2]
                    created_info_tx_hash = created_info[3]
                except StopIteration as e: # TODO assert exception type here
                    import pdb; pdb.set_trace()
                    break

                try:
                    cur_contract = next(contract_iterator)
                except StopIteration as e: # TODO assert exception type here
                    import pdb; pdb.set_trace()
                    break

    for contract in updated_contracts:
        new_db.add_contract_no_commit(contract)
    new_db.connection.commit()

    for code_hash_entry in db.iterate_code_hashes():
        new_db.add_code_hash_no_commit(code_hash_entry)
    new_db.connection.commit()

def init_final_dataset():
    db = DB.load('all_contracts_filtered2.db')

    selfdestructable_contracts = {} # map creator address -> [selfdestructable contract address]

    cursor = db.connection.cursor()

    # query ephemeral creators by on-chain usage
    db.create_ephemerals_creators()
    with open("analysis-results/genesis-to-12799316/creators-of-ephemeral-contracts.csv") as f:
        addrs = [(line.strip('\n').split(',')[0], int(line.strip('\n').strip(' ').split(',')[1])) for line in f.readlines()[1:]]

        for addr, count in addrs:
            db.add_ephemeral_creator_no_commit(addr, count)

        db.connection.commit()

    # load all account balances from csvs and shove them into the db
    db.create_accounts_balances()
    for file_name in sorted(glob.glob('ethereum-account-balances/*.csv')):
        with open(file_name, 'r') as f:
            for line in f:
                break # ignore the header

            for line in f:
                line_parts = line.strip('\n').split(',')
                addr = line_parts[0]
                balance = int(line_parts[1])
                if balance != 0:
                    db.add_account_balance_no_commit(line_parts[0], balance)

        print(file_name)
        db.connection.commit()

    # create table with previously-reinited addresses.
    db.create_prev_reinited()
    with open('analysis-results/genesis-to-12799316/redeployed-addrs.csv', 'r') as f:
        for line in f:
            break # skip header

        for line in f:
            parts = line.split(',')
            addr = parts[0]
            count = int(parts[1].strip(' ').strip('\n'))
            db.add_prev_reinited_no_commit(addr, count)

    db.connection.commit()

    if False:
        # TODO do trace analysis here
        pass

    import pdb; pdb.set_trace()

    # get count of existing selfdestructable contracts with contract creator that exist at previously-reinited addresses
    count_doobydobab = '''
        select count(*) from contracts 
            left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
            where codeHashes.code_hash IS NOT NULL
                  and contracts.code_hash IS NOT NULL
                  and isSelfdestructable=true
                  and contracts.address in (select address from prev_reinited)
                  and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash));'''

    count_active_doobydobab = '''
        select count(*) from contracts 
            left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
            left join address_traces on (contracts.address = address_traces.address)
            where codeHashes.code_hash IS NOT NULL
                  and address_traces.address is not null
                  and contracts.code_hash IS NOT NULL
                  and isSelfdestructable=true
                  and contracts.address in (select address from prev_reinited)
                  and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash));'''

    # get existing selfdestructable contracts with contract creator that exist at previously-reinited addresses:
    doobydobab = '''
        select contracts.address, creator, accounts_balances.balance from contracts 
            left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
            left join accounts_balances on (contracts.address = accounts_balances.address)
            where codeHashes.code_hash IS NOT NULL
                  and contracts.code_hash IS NOT NULL
                  and accounts_balances.balance IS NOT NULL
                  and isSelfdestructable=true
                  and contracts.address in (select address from prev_reinited)
                  and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash))
            order by accounts_balances.balance desc limit 10;'''

    # same but order the results by recent activity
    doobydobab2 = '''
        select contracts.address, creator, address_traces.count from contracts 
            left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
            left join address_traces on (contracts.address = address_traces.address)
            where codeHashes.code_hash IS NOT NULL
                  and contracts.code_hash IS NOT NULL
                  and address_traces.address IS NOT NULL
                  and isSelfdestructable=true
                  and contracts.address in (select address from prev_reinited)
                  and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash))
            order by address_traces.count desc;'''

    # ephemeral 
    contract_creators_of_ephemerals_count_ordered = '''
        select contracts.address, address_traces.count from contracts
            left join address_traces on (address_traces.address = contracts.address)
            left join ephemerals_creators on (address_traces.address = ephemerals_creators.address)
            left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
            where address_traces.address IS NOT NULL
                and ephemerals_creators.address IS NOT NULL
                and codeHashes.code_hash IS NOT NULL
                and hasCreate2Op = True
            order by address_traces.count desc;'''

    contract_creators_of_ephemerals_balance_ordered = '''
        select contracts.address, accounts_balances.balance from contracts
            left join ephemerals_creators on (contracts.address = ephemerals_creators.address)
            left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
            left join accounts_balances on (contracts.address = accounts_balances.address)
            where ephemerals_creators.address IS NOT NULL
                and accounts_balances.balance IS NOT NULL
                and codeHashes.code_hash IS NOT NULL
                and hasCreate2Op = True
            order by accounts_balances.balance desc;'''

    # count of existing ephemeral creators
    contract_creators_of_ephemerals_num_entries = '''
        select count(*) from contracts
            left join ephemerals_creators on (contracts.address = ephemerals_creators.address)
            left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
            where ephemerals_creators.address IS NOT NULL
                and codeHashes.code_hash IS NOT NULL
                and hasCreate2Op = True;'''
    # TODO contracts which created ephemerals at reinited addresses

    # contracts that are less-likely to be affected

    # query to get existing selfdestructable contracts, created by a create2-containing
    # parent contract that doesn't contain create
    # that have previously reinited
    # TODO remove: it's useless
    selfdestructable_reinitable_order_balance_query = '''
        select contracts.address, creator, accounts_balances.balance from contracts 
            left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
            left join accounts_balances on (contracts.address = accounts_balances.address)
            where codeHashes.code_hash IS NOT NULL
                  and contracts.code_hash IS NOT NULL
                  and accounts_balances.balance IS NOT NULL
                  and isSelfdestructable=true
                  and contracts.address in (select address from prev_reinited)
                  and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op=true and hasCreateOp=false)
            order by accounts_balances.balance desc limit 10;'''
    import pdb; pdb.set_trace()

    contract_creators_of_ephemerals = '''
        select contracts.address, address_traces.count from contracts
            left join address_traces on (address_traces.address = contracts.address)
            left join ephemerals_creators on (address_traces.address = ephemerals_creators.address)
            left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
            where address_traces.address IS NOT NULL
                and ephemerals_creators.address IS NOT NULL
                and codeHashes.code_hash IS NOT NULL
                and hasCreate2Op = True
            order by address_traces.count desc;'''
    import pdb; pdb.set_trace()


    # query for selfdestructable contracts created by a contract with create2 (and not create).  these are guaranteed to be reinitable
    # TODO: we assume the account was created by the latest bytecode at the creator address (the creator could have redeployed).  this can create false positives/negatives.
    selfdestructable_reinitable_query = '''
        select count(*) from contracts 
            left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
            left join address_traces on (address_traces.address = contracts.address)
            where address_traces.address IS NOT NULL
                  and codeHashes.code_hash IS NOT NULL
                  and isSelfdestructable=true
                  and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op=true and hasCreateOp=false);'''
    res = cursor.execute(selfdestructable_reinitable_query)
    selfdestructable_reinitable = []
    selfdestructable_reinitable_creators = []
    for row in res:
        selfdestructable_reinitable.append(row[0])
        selfdestructable_reinitable_creators.append(row[1])

    selfdestructable_reinitable_creators = set(selfdestructable_reinitable_creators)

    # query for selfdestructable contracts created by a contract that contained both create and create2.  we will want to trace the creation tx to determine
    # if these were created with create2.
    selfdestructable_indeterminant_query = '''
        select contracts.address, creator, address_traces.count from contracts 
            left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
            left join address_traces on (address_traces.address = contracts.address)
            where address_traces.address IS NOT NULL
                  and codeHashes.code_hash IS NOT NULL
                  and isSelfdestructable=true
                  and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op=true and hasCreateOp=true)
                  and not address in (select address from prev_reinited where address = contracts.address)
            order by address_traces.count desc limit 10;'''

    selfdestructable_indeterminant_count_query = '''
        select count(*) from contracts 
            left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
            left join address_traces on (address_traces.address = contracts.address)
            where address_traces.address IS NOT NULL
                  and codeHashes.code_hash IS NOT NULL
                  and isSelfdestructable=true
                  and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op=true and hasCreateOp=true)
                  and not contracts.address in (select prev_reinited.address from prev_reinited where prev_reinited.address = contracts.address);'''

    # query to find all selfdestructable contracts created by EOAs
    # we may want to trace all of these to find out which ones are potentially-reinitable
    # but these are less-likely to be broken than in situations with contract-created re-initables/ephemerals.
    selfdestructable_reinitable_eoa_creator_query = '''
        select contracts.address, creator, address_traces.count from contracts 
            left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
            left join address_traces on (address_traces.address = contracts.address)
            where address_traces.address IS NOT NULL
                  and codeHashes.code_hash IS NOT NULL
                  and isSelfdestructable=true
                  and not creator in (select contracts.address from contracts)
            order by address_traces.count desc limit 10;'''

    # TODO query contract creators of selfdestructable by on-chain usage


    # TODO convert the above results to sets and make sure the size doesn't change (there shouldn't be repeated addresses in contracts)

    assert len(set(selfdestructable_reinitable)) == len(selfdestructable_reinitable)
    assert len(set(selfdestructable_reinitable_eoa_creators)) == len(selfdestructable_reinitable_eoa_creators)
    assert len(set(selfdestructable_indeterminant)) == len(selfdestructable_indeterminant)

    with open('selfdestructable_reinitable.csv', 'w') as f:
        for addr in selfdestructable_reinitable:
            f.write(addr+'\n')

    with open('selfdestructable_reinitable_eoa_creators.csv', 'w') as f:
        for addr in selfdestructable_reinitable_eoa_creators:
            f.write(addr+'\n')

    with open('selfdestructable_indeterminant.csv', 'w') as f:
        for addr in selfdestructable_indeterminant:
            f.write(addr+'\n')

    with open('selfdestructable_reinitable_creators.csv', 'w') as f:
        for addr in selfdestructable_reinitable_creators:
            f.write(addr+'\n')

    with open('selfdestructable_reinitable_eoa_creators_creators.csv', 'w') as f:
        for addr in selfdestructable_reinitable_eoa_creators_creators:
            f.write(addr+'\n')

    with open('selfdestructable_indeterminant_creators.csv', 'w') as f:
        for addr in selfdestructable_indeterminant_creators:
            f.write(addr+'\n')

if __name__ == "__main__":
    # shove all the contracts from entire history into a db
    # main()

    # filter contracts, only keeping the entry with the highest blockNumber (latest incarnation)
    # ingest_all_contracts_filter()

    # fill-in the creator/tx-hash of each alive contract
    # fill_in_creator_tx_hash()

    # fill in final dataset for what can be determined, marking accounts that need to be queried
    init_final_dataset()

    # do queries.

    # fill in remaining data
