USE test;

INSERT INTO login (username, password, roles) VALUES (
	'jean.dupond@gmail.com', 
	'{bcrypt}$2a$10$Kd7BZwLmFIfoYDttqaJ6V.Lsp4xe31Qc9ha/gBYFGYgnAMvY758vm', 
	{ 'ROLE_ACCOUNT' }
);

INSERT INTO login (username, password, roles) VALUES (
	'jean.dupont@gmail.com', 
	'{bcrypt}$2a$10$Kd7BZwLmFIfoYDttqaJ6V.Lsp4xe31Qc9ha/gBYFGYgnAMvY758vm', 
	{ 'ROLE_OTHER' }
);
