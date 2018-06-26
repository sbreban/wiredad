drop table if exists user_device;
drop table if exists user_age_bracket;
drop table if exists device_block;
drop table if exists users;
drop table if exists domain_age_bracket;
drop table if exists age_brackets;
drop table if exists devices;
drop table if exists domains;

create table users
(
  id       integer primary key,
  name     varchar(50),
  username varchar(50),
  password varchar(50),
  token    varchar(50),
  admin    int
);

create table age_brackets
(
  id       integer primary key,
  name     varchar(50),
  age_range varchar(50)
);

create table devices
(
  id       integer primary key,
  name     varchar(50),
  mac_addr varchar(50),
  ip_addr  varchar(50)
);

CREATE TABLE user_device
(
  user_id int,
  device_id int,
  CONSTRAINT user_device_user_fk FOREIGN KEY (user_id) REFERENCES users (id),
  CONSTRAINT user_device_device_fk FOREIGN KEY (device_id) REFERENCES devices (id)
);

CREATE TABLE user_age_bracket
(
  user_id int,
  bracket_id int,
  CONSTRAINT user_age_bracket_user_fk FOREIGN KEY (user_id) REFERENCES users (id),
  CONSTRAINT user_age_bracket_bracket_fk FOREIGN KEY (bracket_id) REFERENCES age_brackets (id)
);


CREATE TABLE device_block
(
  device_id int,
  from_time string,
  to_time string,
  block int,
  CONSTRAINT device_block_device_fk FOREIGN KEY (device_id) REFERENCES devices (id)
);


create table domains
(
  id     integer primary key,
  name   varchar(50),
  domain varchar(50),
  block  int
);

CREATE TABLE domain_age_bracket
(
  domain_id int,
  bracket_id int,
  CONSTRAINT domain_age_bracket_domain_fk FOREIGN KEY (domain_id) REFERENCES domains (id),
  CONSTRAINT domain_age_bracket_bracket_fk FOREIGN KEY (bracket_id) REFERENCES age_brackets (id)
);

insert into users values (1, 'Senior', 'sr', 'sr', '', 0);
insert into users values (2, 'John F. Kennedy', 'jfk', 'jfk', 'tn4vhcI1Z7BkHeb4E5ZUwA', 1);
insert into users values (3, 'Franklin D. Roosevelt', 'fdr', 'fdr', '', 1);

insert into age_brackets values (1, 'Teen', '14+');
insert into age_brackets values (2, 'Pre-K', '7-14');
insert into age_brackets values (3, 'Kid', '0-7');

insert into user_age_bracket values (2, 2);
insert into user_age_bracket values (3, 1);

insert into devices values (1, 'phone', 'DC:0B:34:CC:B0:00', '192.168.0.103');
insert into devices values (2, 'tablet', 'DC:0B:00:CC:B0:FF', '192.168.0.104');
insert into devices values (3, 'windows-phone', '3c:83:75:d0:da:c4', '192.168.0.105');

insert into user_device values (2, 1);
insert into user_device values (2, 2);
insert into user_device values (3, 3);

insert into domains values (1, 'Facebook', 'facebook.com', 0);
insert into domains values (2, 'Instagram', 'instagram.com', 0);
insert into domains values (3, 'Strava', 'strava.com', 0);