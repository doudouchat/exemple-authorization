USE test;

CREATE TABLE login (
	login text PRIMARY KEY,
	password text,
	disabled boolean,
	account_locked boolean,
	roles set<text>
);
