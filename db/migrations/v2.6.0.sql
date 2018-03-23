alter table user add column totp_key varchar(80) comment 'two factor key';
alter table session add column data text comment 'json encode format extra session data';