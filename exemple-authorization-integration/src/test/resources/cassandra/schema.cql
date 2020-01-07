CREATE KEYSPACE IF NOT EXISTS test 
  WITH REPLICATION = { 
   'class' : 'NetworkTopologyStrategy', 
   'datacenter1' : 1
};

USE test;

CREATE TABLE IF NOT EXISTS login (
	login text PRIMARY KEY,
	password text,
	disabled boolean,
	account_locked boolean,
	roles set<text>
);