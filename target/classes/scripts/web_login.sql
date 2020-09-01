create table authority (id bigint not null auto_increment, role varchar(255), primary key (id)) engine=InnoDB;
create table user (id bigint not null auto_increment, account_non_expired bit, account_non_locked bit, credentials_non_expired bit, enabled bit, password varchar(255), username varchar(255), primary key (id)) engine=InnoDB;
create table user_authority (user_id bigint not null, authority_id bigint not null, primary key (user_id, authority_id)) engine=InnoDB;
alter table user_authority add constraint FKgvxjs381k6f48d5d2yi11uh89 foreign key (authority_id) references authority (id);
alter table user_authority add constraint FKpqlsjpkybgos9w2svcri7j8xy foreign key (user_id) references user (id);
