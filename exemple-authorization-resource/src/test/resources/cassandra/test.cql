USE test;

CREATE TABLE login (
	username text PRIMARY KEY,
	password text,
	disabled boolean,
	account_locked boolean,
	roles set<text>
);
