drop table if exists user_client;
drop table if exists client_domain;
drop table if exists users;
drop table if exists clients;
drop table if exists domains;

create table users
(
  id       int primary key,
  username varchar(50),
  password varchar(50)
);

create table clients
(
  id       int primary key,
  name     varchar(50),
  mac_addr varchar(50),
  ip_addr  varchar(50)
);

CREATE TABLE user_client
(
  user_id int,
  client_id int,
  CONSTRAINT user_client_user_fk FOREIGN KEY (user_id) REFERENCES users (id),
  CONSTRAINT user_client_client_fk FOREIGN KEY (client_id) REFERENCES clients (id)
);

create table domains
(
  id     int primary key,
  name   varchar(50),
  domain varchar(50)
);

CREATE TABLE client_domain
(
  client_id int,
  domain_id int,
  block     int,
  CONSTRAINT client_domain_client_fk FOREIGN KEY (client_id) REFERENCES clients (id),
  CONSTRAINT client_domain_domain_fk FOREIGN KEY (domain_id) REFERENCES domains (id)
);

insert into users values (1, 'sbreban', 'sbreban');

insert into clients values (1, 'raspberry', 'a', '192.168.0.103');
insert into clients values (2, 'pc', 'b', '192.168.0.104');

insert into user_client values (1, 1);

insert into domains values (1, 'Facebook', 'facebook.com');
insert into domains values (2, 'Instagram', 'instagram.com');
insert into domains values (3, 'Strava', 'strava.com');

insert into client_domain values (1, 1, 0);
insert into client_domain values (1, 2, 0);
insert into client_domain values (1, 3, 0);
