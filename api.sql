CREATE SCHEMA api;
GRANT USAGE on SCHEMA api to PUBLIC;

DO LANGUAGE plpgsql $$ BEGIN CREATE USER sessioner; EXCEPTION when duplicate_object THEN
  RAISE NOTICE 'sessioner already exists';
  END $$;

CREATE OR REPLACE FUNCTION api.json_text(json) RETURNS text IMMUTABLE LANGUAGE sql AS $$
  SELECT ('['||$1||']')::json->>0 $$;

CREATE OR REPLACE FUNCTION api.select(jparms json) RETURNS json LANGUAGE plpgsql AS $$
DECLARE
  result json;
  schm varchar; tbl varchar;  flds varchar; lmt varchar; offs varchar; ws json;
  fnn varchar[];
  rec json; mor json;
  inter json[];
  cmd text; flag text; wher text; lit text; wf text;
  first boolean;
  cols text[];
BEGIN
  tbl = coalesce(jparms->>'table','');
  fnn = regexp_split_to_array(tbl,'\.');
  if array_length(fnn, 1) = 2 THEN
    schm = quote_ident(fnn[1]) || '.';
    tbl = quote_ident(fnn[2]);
  ELSE
    schm = '';
    tbl = quote_ident(fnn[1]);
  END IF;
  select string_agg(quote_ident( api.json_text(n) ),',') into flds from json_array_elements(jparms->'fields') as n;
  flds= coalesce(flds,'*');
  
    -- this is conceivably dangerous, there is no default limit.  Perhaps the default limit should be 99 or something?
  lmt = coalesce( ' LIMIT ' || ((jparms->'limit')::text::int), '');
  offs = coalesce( ' OFFSET ' || ((jparms->'offset')::text::int), '');
  
  ws = jparms -> 'where'; -- I expect this to be a fieldname/literal array
  wf = quote_ident(ws ->> 0);
  lit = (ws -> 1) :: text;
  if lit like '"%' then lit := quote_literal(ws ->> 1); end if;
  
  wher = coalesce( ' WHERE ' || wf || '=' || lit, '');
  DROP TABLE IF EXISTS "S 1";
  cmd = 'CREATE TEMPORARY TABLE "S 1" ON COMMIT DROP AS SELECT  ' || flds || ' FROM ' || schm || tbl || wher || offs || lmt ;
  raise notice 'select: %', cmd;
  execute cmd;

  flag = jparms ->> 'asarray';
  if flag IS NOT NULL and (flag = '1' OR flag='true') THEN
    first := true;
    for rec in select row_to_json("S 1") as rec from "S 1"
    loop
      if first then 
        first := false;
        mor := array_to_json(array(select json_object_keys(rec)));
        inter := array_append(inter, mor);
      end if;
      mor := array_to_json(array(select value from json_each(rec)));
      inter := array_append(inter, mor);
    end loop;
    result := array_to_json( inter) ;
  ELSE
    SELECT array_to_json( coalesce(array_agg(row_to_json(a)),'{}')) FROM "S 1" AS a INTO result;
  END IF;
  return result;
END $$;


CREATE OR REPLACE FUNCTION api.execute(jparms json) RETURNS json LANGUAGE plpgsql AS $$
DECLARE
  schm varchar; proc varchar;
  args json;
  fnn varchar[];
  result json;
  cmd text; var text; flag text; fnam text;
  rec json; mor json;
  inter json[];
  
BEGIN
  fnam = coalesce(jparms->>'function','');
  fnn = regexp_split_to_array(fnam, '\.');
  if array_length(fnn, 1) = 2 THEN 
    schm = quote_ident(fnn[1]) || '.';
    proc = quote_ident(fnn[2]);
  ELSE 
    schm = '';
    proc = quote_ident(fnn[1]);
  END IF;
  
  args = jparms->'args';
  cmd = 'CREATE TEMPORARY TABLE "X 1" ON COMMIT DROP AS SELECT  * FROM ' || schm || proc || '(';
  for x in 1..json_array_length(args) loop
    if x > 1 then cmd := cmd || ','; end if;
    var := (args -> (x-1))::text;
    if var like '"%' then var := quote_literal(args ->> (x-1)); end if;
    cmd := cmd || var;
  end loop;
  cmd := cmd || ')';
--  BEGIN DROP TABLE IF EXISTS "X 1"; EXCEPTION WHEN OTHERS THEN END;
  RAISE NOTICE '%', cmd;
  execute cmd;
  
  flag = jparms ->> 'asarray';
  if flag IS NOT NULL and (flag = '1' OR flag='true') THEN
    for rec in select row_to_json("X 1") as rec from "X 1" loop
      mor := array_to_json(array(select value from json_each(rec)));
      inter := array_append(inter, mor);
    end loop;
    result := array_to_json(inter);
  ELSE
    SELECT array_to_json( coalesce(array_agg(row_to_json(a)),'{}')) FROM "X 1" AS a INTO result;
  END IF;
  return result;
END $$;

CREATE OR REPLACE FUNCTION api.json_type(j json) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
  RETURN case substring(ltrim(j::text), 1, 1)
      when '[' then 'array'
      when '{' then 'object'
      else 'other'
  END;
END $$;

CREATE OR REPLACE FUNCTION api.eval(jparms json) RETURNS json LANGUAGE plpgsql AS $$
DECLARE
  schm varchar; proc varchar;
  args json;
  fnn varchar[];
  result json;
  cmd text; var text; flag text; fnam text;
  rec json; mor json;
  inter json[];
  jk text;
  jv text;
  first_time bool;
BEGIN
  RAISE NOTICE 'api.eval(%)', jparms;
  fnam = coalesce(jparms->>'function','');
  fnn = regexp_split_to_array(fnam, '\.');
  if array_length(fnn, 1) = 2 THEN
    schm = quote_ident(fnn[1]) || '.';
    proc = quote_ident(fnn[2]);
  ELSE
    schm = '';
    proc = quote_ident(fnn[1]);
  END IF;

  args = jparms->'args';
  cmd = 'SELECT to_json(' || schm || proc || '(';

  IF api.json_type(args) = 'array' THEN
    for x in 1..json_array_length(args) loop
      if x > 1 then cmd := cmd || ','; end if;
      var := (args -> (x-1))::text;
      if var like '"%' then var := quote_literal(args ->> (x-1)); end if;
      cmd := cmd || var;
    end loop;
  ELSE
    first_time = true;
    FOR jk,jv IN SELECT * FROM json_each_text(args)
    LOOP
      if NOT first_time THEN cmd := cmd || ', '; ELSE first_time = false; END IF;
      cmd := cmd || quote_ident(jk) || ' := ' || quote_literal(jv);
    END LOOP;
  END IF;
  cmd := cmd || '))';

  raise notice 'pre-cmd: %', cmd;

  execute cmd into result;
  return result;

END $$;

CREATE OR REPLACE FUNCTION api.get_path(jparms json) RETURNS json LANGUAGE plpgsql AS $$
DECLARE
  pth varchar;
  args json;
BEGIN
  pth = jparms ->> 'path';
  args := json_agg(x.*) FROM (SELECT pth as function, jparms-> 'args' as args) as X;
  args := args -> 0;

  RAISE NOTICE 'get_path %(%)', pth, args;
  if pth IS NULL OR pth = '' THEN RETURN NULL;
  ELSE return api.eval( args ) ;

  END IF;
END $$;

CREATE OR REPLACE FUNCTION api.passthrough(op text, jparms json) RETURNS json LANGUAGE plpgsql AS $$
DECLARE
  result json;
BEGIN
  if op = 'select' then return api.select(jparms);
  elsif op = 'execute' then return api.execute(jparms);
  elsif op = 'eval' then return api.eval(jparms);
  elsif op = 'get' then return api.get_path(jparms);
  else raise exception 'invalid api.passthrough op: %', op;
  end if;
END $$;

CREATE OR REPLACE FUNCTION api.api(meta text, req text ) RETURNS json LANGUAGE plpgsql AS $$
DECLARE
  jreq json;
  jmeta json;
  vuserid varchar;
  sessemail varchar;
  ipa varchar;
  sessid varchar;
  comp varchar;
  rol varchar;
  vurs varchar;
  interc varchar;
  vreasons varchar;
  result json;
  session_state json;
BEGIN
  raise notice 'meta=%, req=%', meta, req;
  jmeta := meta::json;
  jreq := req::json;

  sessid := jmeta ->> 'session_id';
  ipa := jmeta->>'ip_address';

  IF sessid is NULL OR (req is NOT NULL AND (jreq ->> 'op') = 'anonymous') THEN
    return api.passthrough(jreq->>'op', jreq);
  ELSE 
  -- the check_session stored procedure should probably also take IP address and USER_AGENT
    session_state := api.check_session(sessid);
    if req IS NULL OR ( jreq ->>'op' = 'get' AND  jreq->>'path' = '') THEN
      return session_state;
    ELSE
      jreq := req::json; -- convert request to JSON
      PERFORM api.become(session_state);
      return api.passthrough(jreq->>'op', jreq);
    END IF;
  END IF;
END $$;
GRANT EXECUTE on FUNCTION api.api(text, text) TO PUBLIC;


create table api.db_session_table(pid int primary key default pg_backend_pid(), start timestamp default now(), state json);

create view api.db_session as select state from api.db_session_table where pid = pg_backend_pid();
grant select,insert,update on api.db_session to public;

create or replace function api.get_db_session()  returns json language plpgsql as $$
declare result json; begin
  select state from api.db_session into result;
  return result;
end $$;
grant execute on function api.get_db_session() to public;

create or replace function api.set_db_session(st json) returns void language plpgsql as $$
begin
  if (1 = (select count(*) from api.db_session)) then update api.db_session set state = st;
  else insert into api.db_session values(st);
  end if;
end $$;
grant execute on function api.set_db_session(json) to public;


CREATE TABLE api.web_session_table (
  session_id varchar primary key,
  db_session_id int unique default pg_backend_pid(),
  user_id varchar,
  login_id varchar,
  login_redirect varchar,
  role varchar,
  ip varchar,
  last_update timestamp default now(),
  created timestamp default now()
);
grant insert, update on api.web_session_table to sessioner;

create view api.web_session as select user_id, login_id, login_redirect, role, ip, last_update, created
  from api.web_session_table where db_session_id = pg_backend_pid();
grant select, insert on api.web_session to public;
grant update(last_update) on api.web_session to public;

create or replace function touch_session() returns void language plpgsql as $$
BEGIN UPDATE api.web_session SET last_update = now(); END $$;

CREATE OR REPLACE FUNCTION api.check_session(IN sess character varying) RETURNS json LANGUAGE plpgsql VOLATILE
SECURITY DEFINER AS $$
DECLARE res json;
BEGIN
   UPDATE api.session as t set last_update = current_timestamp where session_id=sess returning row_to_json(session.*) INTO res;
   RETURN res;
END $$;

CREATE or REPLACE FUNCTION api.test() returns json language plpgsql as $$ BEGIN
  return to_json('hello'::text); END $$;
  
