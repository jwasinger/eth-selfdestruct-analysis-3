# Selfdestruct Analysis 3

This repository contains tools to build the dataset summarized in the [third selfdestruct removal analysis](https://hackmd.io/X-waAY49SrW9i36SKOVuGQ).

## Usage

### Download the Datasets

Each raw dataset should be retrieved using BigQuery, exported to a GCS bucket with the naming format `data-*.csv` and downloaded to the specified folder:

##### All Ethereum Contracts (Past and Present)

Query:
```
SELECT address, bytecode, block_number, block_hash FROM `bigquery-public-data.crypto_ethereum.contracts` order by address;
```

Dataset goes into `all-contracts` folder.

##### Recent Execution Traces

Query:
```
select block_hash, transaction_hash,  trace_id, block_number, transaction_index, from_address, to_address, trace_type, call_type, status, value from `bigquery-public-data.crypto_ethereum.traces`
  where block_number > 14807702 and block_number <= 14907702
    order by block_number asc, transaction_index asc;
```

Dataset goes into `full-recent-traces` folder.

##### Balances for All Existing Contracts with Nonzero Balance

Query:
```
select distinct `bigquery-public-data.crypto_ethereum.balances`.address, eth_balance from `bigquery-public-data.crypto_ethereum.balances` join `bigquery-public-data.crypto_ethereum.contracts` on (`bigquery-public-data.crypto_ethereum.balances`.address = `bigquery-public-data.crypto_ethereum.contracts`.address) where `bigquery-public-data.crypto_ethereum.contracts`.address is not null and `bigquery-public-data.crypto_ethereum.balances`.eth_balance != 0 order by address;
```

Dataset goes into the `ethereum-account-balances` folder

### Run the Analysis

```
> python3 rename-files.py
> python3 analyze.py
> python3 create_all_contracts_db.py
> python3 trace_frequency.py
```

The analysis scripts produce a Sqlite dataset at `all_contracts_filtered2.db`.

### Queries from the report

##### Count of selfdestructable contracts created by a create2-containing account
```
select count(*) from contracts 
             left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
                   where codeHashes.code_hash IS NOT NULL
                   and isSelfdestructable=true
                   and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op=true and hasCreateOp=false);
```

##### Count of create2-containing creators of selfdestructable contracts
```
select count(distinct creator) from contracts 
             left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
                   where codeHashes.code_hash IS NOT NULL
                   and isSelfdestructable=true
                   and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op=true and hasCreateOp = false);
```

##### Count of selfdestructable contracts created by a create2-and-create-containing account
```
select count(*) from contracts 
             left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
                   where codeHashes.code_hash IS NOT NULL
                   and isSelfdestructable=true
                   and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op=true and hasCreateOp=true);
```

##### Count of create2-and-create-containing creators of selfdestructable contracts
```
select count(distinct creator) from contracts 
             left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
                   where codeHashes.code_hash IS NOT NULL
                   and isSelfdestructable=true
                   and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op=true and hasCreateOp = true);
```

##### Count of selfdestructable contracts created by a create2-containing account that were recently active
```
select count(*) from contracts 
             left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
             left join address_traces on (address_traces.address = contracts.address)
             where address_traces.address IS NOT NULL
                   and codeHashes.code_hash IS NOT NULL
                   and isSelfdestructable=true
                   and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op=true);
```

##### Count of selfdestructable contracts created by a create2-containing account that have non-zero Eth balance
```
select count(*) from contracts 
             left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
             left join accounts_balances on (accounts_balances.address = contracts.address)
             where accounts_balances.address IS NOT NULL
                   and codeHashes.code_hash IS NOT NULL
                   and isSelfdestructable=true
                   and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op=true);
```

##### Count of non-zero balance create2-containing creators of selfdestructable contracts
```
select count(*) from contracts 
	left join accounts_balances on (accounts_balances.address = contracts.address)
        where contracts.address in (
		select distinct(contracts.creator) from contracts 
			     left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
				   where codeHashes.code_hash IS NOT NULL
				   and isSelfdestructable=true
				   and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op=true))
	and accounts_balances.balance is not null;
```

##### Top Balance Creators of selfdestructable contracts created by create2-containing accounts
```
select contracts.address, accounts_balances.balance from contracts 
	left join accounts_balances on (accounts_balances.address = contracts.address)
        where contracts.address in (
		select distinct(contracts.creator) from contracts 
			     left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
				   where codeHashes.code_hash IS NOT NULL
				   and isSelfdestructable=true
				   and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op=true))
	and accounts_balances.balance is not null
        and contracts.address is not null
	order by accounts_balances.balance desc limit 10;
```

##### Count of recently-active creators of selfdestructable contracts created by create2-containing addresses
```
select count(*) from contracts 
	left join address_traces on (address_traces.address = contracts.address)
        where contracts.address in (
		select distinct(contracts.creator) from contracts 
			     left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
				   where codeHashes.code_hash IS NOT NULL
				   and isSelfdestructable=true
				   and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op=true))
	and address_traces.address is not null;
```

##### Recently-active creators of selfdestructable contracts created by create2-containing addresses
```
select contracts.address, address_traces.count from contracts 
	left join address_traces on (address_traces.address = contracts.address)
        where contracts.address in (
		select distinct(contracts.creator) from contracts 
			     left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
				   where codeHashes.code_hash IS NOT NULL
				   and isSelfdestructable=true
				   and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op=true))
	and address_traces.address is not null
        and contracts.address is not null
	order by address_traces.count desc limit 10;
```

##### number of selfdestructable contracts deployed at previously-reinited addresses by create2-containing creators.
```
select count(*) from contracts
	left join prev_reinited on (contracts.address = prev_reinited.address)
	left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
	where codeHashes.code_hash is not null
	and prev_reinited.address is not null
	and creator in (select address from contracts left join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op = true)
	and isSelfdestructable = true;
```

##### number of create2-containing creators that have existing selfdestructable child contracts at previously-reinited addresses
```
select count(distinct creator) from contracts
	left join prev_reinited on (contracts.address = prev_reinited.address)
	left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
	where codeHashes.code_hash is not null
	and prev_reinited.address is not null
	and creator in (select address from contracts left join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op = true)
	and isSelfdestructable = true;
```

##### number of non-zero balance create2-containing creators that have selfdestructable children at previously-reinited addresses
```
select count(*) from contracts 
	left join accounts_balances on (accounts_balances.address = contracts.address)
        where contracts.address in (
		select distinct(contracts.creator) from contracts 
			     left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
			     left join prev_reinited on (contracts.address = prev_reinited.address)
				   where codeHashes.code_hash IS NOT NULL
                                   and prev_reinited.address is not null
				   and isSelfdestructable=true
				   and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op=true))
	and accounts_balances.balance is not null
        and contracts.address is not null
	order by accounts_balances.balance desc limit 10;
```

##### Top create2-containing creators that have selfdestructable children at previously-reinited addresses (balance ranked)
```
select contracts.address, accounts_balances.balance from contracts 
	left join accounts_balances on (accounts_balances.address = contracts.address)
        where contracts.address in (
		select distinct(contracts.creator) from contracts 
			     left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
			     left join prev_reinited on (contracts.address = prev_reinited.address)
				   where codeHashes.code_hash IS NOT NULL
                                   and prev_reinited.address is not null
				   and isSelfdestructable=true
				   and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op=true))
	and accounts_balances.balance is not null
        and contracts.address is not null
	order by accounts_balances.balance desc limit 10;
```

##### count of recently-active create2-containing creators that have selfdestructable children at previously-reinited addresses
```
select count(*) from contracts
	left join address_traces on (address_traces.address = contracts.address)
        where contracts.address in (
		select distinct(contracts.creator) from contracts 
			     left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
			     left join prev_reinited on (contracts.address = prev_reinited.address)
				   where codeHashes.code_hash IS NOT NULL
                                   and prev_reinited.address is not null
				   and isSelfdestructable=true
				   and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op=true))
	and address_traces.count is not null
        and contracts.address is not null;
```

##### top create2-containing creators with recent activity that have selfdestructable children at previously-reinited addresses

```
select contracts.address, address_traces.count from contracts
	left join address_traces on (address_traces.address = contracts.address)
        where contracts.address in (
		select distinct(contracts.creator) from contracts 
			     left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
			     left join prev_reinited on (contracts.address = prev_reinited.address)
				   where codeHashes.code_hash IS NOT NULL
                                   and prev_reinited.address is not null
				   and isSelfdestructable=true
				   and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where hasCreate2Op=true))
	and address_traces.count is not null
        and contracts.address is not null
	order by address_traces.count desc limit 10;
```

##### Count of alive previously-reinited addresses
```
select count(*) from contracts
             left join prev_reinited on (contracts.address = prev_reinited.address)
             where prev_reinited.address is not null;
```

##### count of selfdestructable contracts (created by contracts) at previously-reinited addresses

```
select count(*) from contracts 
	left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
	where codeHashes.code_hash IS NOT NULL
		and contracts.code_hash IS NOT NULL
		and isSelfdestructable=true
		and contracts.address in (select address from prev_reinited)
		and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash));
```

##### count of selfdestructable contracts (created by contracts) at previously-reinited addresses that were recently active
```
select count(*) from contracts 
            left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
            left join address_traces on (contracts.address = address_traces.address)
            where codeHashes.code_hash IS NOT NULL
                  and address_traces.address is not null
                  and contracts.code_hash IS NOT NULL
                  and isSelfdestructable=true
                  and contracts.address in (select address from prev_reinited)
                  and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash));
```

##### count of all alive previously-reinited addresses that are selfdestructable and have non-zero balance, create2-containing creators
```
select count(*) from contracts
             left join prev_reinited on (contracts.address = prev_reinited.address)
             left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
             left join accounts_balances on (contracts.address = accounts_balances.address)
             where codeHashes.isSelfdestructable = true and
             accounts_balances.address is not null and
             codeHashes.code_hash is not null and
             prev_reinited.address is not null
	     and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where codeHashes.hasCreate2Op is true);
```

##### existing selfdestructable contracts that exist at previously-reinited addreses with create2-containing contract creator ordered by accounts with highest balance
```
select contracts.address, creator, accounts_balances.balance from contracts 
            left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
            left join accounts_balances on (contracts.address = accounts_balances.address)
            where codeHashes.code_hash IS NOT NULL
                  and contracts.code_hash IS NOT NULL
                  and accounts_balances.balance IS NOT NULL
                  and isSelfdestructable=true
                  and contracts.address in (select address from prev_reinited)
                  and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash) where codeHashes.hasCreate2Op is true)
            order by accounts_balances.balance desc limit 10;
```

##### Same but ordered by accounts with the most recent activity
```
        select contracts.address, creator, address_traces.count from contracts 
            left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
            left join address_traces on (contracts.address = address_traces.address)
            where codeHashes.code_hash IS NOT NULL
                  and contracts.code_hash IS NOT NULL
                  and address_traces.address IS NOT NULL
                  and isSelfdestructable=true
                  and contracts.address in (select address from prev_reinited)
                  and creator in (select contracts.address from contracts join codeHashes on (contracts.code_hash = codeHashes.code_hash))
            order by address_traces.count desc limit 10;
```

##### Number of alive ephemeral creators
```
        select count(*) from contracts
		where contracts.address in (select address from ephemerals_creators);
```

##### Number of ephemeral creators with non-zero eth balance
```
        select count(*) from contracts
		where contracts.address in (select address from ephemerals_creators)
		and contracts.address in (select address from accounts_balances);
```

##### Number of recently-active ephemeral creators
```
        select count(*) from contracts
		where contracts.address in (select address from ephemerals_creators)
		and contracts.address in (select address from address_traces);
```

##### Top 10 creators of ephemeral contracts ordered by accounts with the most recent activity
```
        select contracts.address, address_traces.count from contracts
            left join address_traces on (address_traces.address = contracts.address)
            left join ephemerals_creators on (address_traces.address = ephemerals_creators.address)
            left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
            where address_traces.address IS NOT NULL
                and ephemerals_creators.address IS NOT NULL
                and codeHashes.code_hash IS NOT NULL
            order by address_traces.count desc limit 10;
```

##### Same but ordered by accounts with highest Eth holdings
```
        select contracts.address, accounts_balances.balance from contracts
            left join ephemerals_creators on (contracts.address = ephemerals_creators.address)
            left join codeHashes on (contracts.code_hash = codeHashes.code_hash)
            left join accounts_balances on (contracts.address = accounts_balances.address)
            where ephemerals_creators.address IS NOT NULL
                and accounts_balances.balance IS NOT NULL
                and codeHashes.code_hash IS NOT NULL
            order by accounts_balances.balance desc limit 10;
```


##### Creators of ephemerals ordered by the number of ephemeral contracts they have created
```
	select contracts.address, ephemerals_creators.count from contracts
            left join ephemerals_creators on (contracts.address = ephemerals_creators.address)
            where ephemerals_creators.address is not null
            order by ephemerals_creators.count desc limit 10;
```
