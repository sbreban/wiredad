drop table if exists client_domain;
drop table if exists clients;
drop table if exists domains;

create table clients
(
  id       int primary key,
  name     varchar(50),
  mac_addr varchar(50),
  ip_addr  varchar(50)
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
    block int,
    CONSTRAINT client_domain_client_fk FOREIGN KEY (client_id) REFERENCES clients (id),
    CONSTRAINT client_domain_domain_fk FOREIGN KEY (domain_id) REFERENCES domains (id)
);

insert into clients values (1, 'raspberry', 'a', '192.168.0.103');
insert into clients values (2, 'pc', 'b', '192.168.0.104');
insert into domains values (1, 'Facebook', 'facebook.com');
insert into client_domain values (1, 1, 0);
