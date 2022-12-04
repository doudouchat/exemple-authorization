CREATE KEYSPACE IF NOT EXISTS test 
  WITH REPLICATION = { 
   'class' : 'NetworkTopologyStrategy', 
   'datacenter1' : 1
};

CREATE TABLE IF NOT EXISTS test.login (
	username text PRIMARY KEY,
	password text,
	disabled boolean,
	account_locked boolean
);
	