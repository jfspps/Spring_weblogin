# (this is not launched automatically)

create table admin_user (id bigint not null auto_increment, admin_user_name varchar(255), primary key (id)) engine=InnoDB;
create table authority (id bigint not null auto_increment, permission varchar(255), primary key (id)) engine=InnoDB;
create table guardian_user (id bigint not null auto_increment, guardian_user_name varchar(255), primary key (id)) engine=InnoDB;
create table role (id bigint not null auto_increment, role_name varchar(255), primary key (id)) engine=InnoDB;
create table role_authority (role_id bigint not null, authority_id bigint not null, primary key (role_id, authority_id)) engine=InnoDB;
create table root_user (id bigint not null auto_increment, root_user_name varchar(255), primary key (id)) engine=InnoDB;
create table teacher_user (id bigint not null auto_increment, teacher_user_name varchar(255), primary key (id)) engine=InnoDB;
create table test_record (id bigint not null auto_increment, record_name varchar(255), user_id bigint, primary key (id)) engine=InnoDB;
create table user (id bigint not null auto_increment, account_non_expired bit, account_non_locked bit, credentials_non_expired bit, enabled bit, password varchar(255), username varchar(255), admin_user_id bigint, guardian_user_id bigint, root_user_id bigint, teacher_user_id bigint, primary key (id)) engine=InnoDB;
create table user_role (user_id bigint not null, role_id bigint not null, primary key (user_id, role_id)) engine=InnoDB;
alter table role_authority add constraint FKqbri833f7xop13bvdje3xxtnw foreign key (authority_id) references authority (id);
alter table role_authority add constraint FK2052966dco7y9f97s1a824bj1 foreign key (role_id) references role (id);
alter table test_record add constraint FKrtp0n6jfsgd9mlkjt5afh2oir foreign key (user_id) references user (id);
alter table user add constraint FK1tagdxo2hjdp74vvyng5bcb2m foreign key (admin_user_id) references admin_user (id);
alter table user add constraint FKn5g8imvob3txhuijeyo7modr2 foreign key (guardian_user_id) references guardian_user (id);
alter table user add constraint FKrnqdtgvwd5b7x31qrqvp2019i foreign key (root_user_id) references root_user (id);
alter table user add constraint FKg5axhs1yu8j6mfihg22m4ywrc foreign key (teacher_user_id) references teacher_user (id);
alter table user_role add constraint FKa68196081fvovjhkek5m97n3y foreign key (role_id) references role (id);
alter table user_role add constraint FK859n2jvi8ivhui0rl0esws6o foreign key (user_id) references user (id);
