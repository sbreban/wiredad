drop table if exists clients;

create table clients
(
  id       int primary key,
  name     varchar(50),
  mac_addr varchar(50),
  ip_addr  varchar(50)
);

insert into clients values (1, 'raspberry', 'a', '192.168.0.103');

drop table if exists domains;

create table domains
(
  id     int primary key,
  name   varchar(50),
  domain varchar(50)
);

insert into domains values (1, 'Facebook', 'facebook.com');