-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
--
-- mod_plpgsql.sql
--
create or replace procedure print0()
as 
$$
begin
drop table if exists output;
create temp table output (id int generated always as identity, line text);
insert into output(line) values('<h3>Hello from PostgreSQL </h3><br>');
end;
$$
language plpgsql;
--
call print1('OK');select line from output order by id;
create or replace procedure print1(parm text)
as 
$$
begin
drop table if exists output;
create temp table output (id int generated always as identity, line text);
insert into output(line) values('<h3>Hello from PostgreSQL: parm=' || parm || '</h3><br>');
end;
$$
language plpgsql;
--
call print1('OK');select line from output order by id;
--
create or replace procedure print2(parm1 text, parm2 text)
as 
$$
begin
drop table if exists output;
create temp table output (id int generated always as identity, line text);
insert into output(line) values('<h3>Hello from PostgreSQL: parm1=' || parm1 || ' parm2=' || parm2 || ' </h3><br>');
end;
$$
language plpgsql;
--
call print2('OK1','OK2');select line from output order by id;
