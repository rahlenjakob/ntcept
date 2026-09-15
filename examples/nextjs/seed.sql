create table orders (
  id      serial primary key,
  email   text        not null,
  total   integer     not null,
  status  text        not null default 'pending',
  created timestamptz not null default now()
);

create unique index orders_one_pending_per_email on orders (email) where status = 'pending';

insert into orders (email, total, status) values
  ('ada@example.com',    4900, 'paid'),
  ('grace@example.com',  12750, 'paid'),
  ('alan@example.com',    899, 'pending');
