create table user (id bigint not null auto_increment, authorisation varchar(255), enabled bit not null, password varchar(255), username varchar(255), primary key (id)) engine=InnoDB;
