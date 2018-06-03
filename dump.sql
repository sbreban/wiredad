drop table if exists user_client;
drop table if exists client_domain;
drop table if exists user_admin;
drop table if exists users;
drop table if exists clients;
drop table if exists domains;

create table users
(
  id       int primary key,
  username varchar(50),
  password varchar(50),
  admin    int
);

CREATE TABLE user_admin
(
  user_id int,
  admin_id int,
  CONSTRAINT user_admin_user_fk FOREIGN KEY (user_id) REFERENCES users (id),
  CONSTRAINT user_admin_admin_fk FOREIGN KEY (admin_id) REFERENCES users (id)
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
  domain varchar(50),
  block  int
);

insert into users values (1, 'sbreban', 'sbreban', 1);
insert into users values (2, 'jr', 'jr', 0);

insert into user_admin values (2, 1);

insert into clients values (1, 'phone', 'a', '192.168.0.103');
insert into clients values (2, 'tablet', 'b', '192.168.0.104');

insert into user_client values (2, 1);
insert into user_client values (2, 2);

insert into domains values (1, 'Facebook', 'facebook.com', 0);
insert into domains values (2, 'Instagram', 'instagram.com', 0);
insert into domains values (3, 'Strava', 'strava.com', 0);
