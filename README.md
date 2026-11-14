-- ============================================================================
-- SHALGALT — Supabase схем (PostgreSQL)
-- Supabase Dashboard → SQL Editor дотор бүтнээр нь нэг удаа ажиллуулна.
-- Хамгаалалт бүхэлдээ сервер талд: RLS + SECURITY DEFINER функцүүд.
-- Зөв хариулт (question_keys) сурагчид ямар ч замаар харагдахгүй.
-- ============================================================================

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------- ХҮСНЭГТҮҮД
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  full_name text not null default '',
  class_name text,
  role text not null default 'student' check (role in ('student','teacher','admin')),
  teacher_requested boolean not null default false,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.questions (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  type text not null check (type in ('single','multi','fill','image')),
  text text not null,
  image text,
  options jsonb not null default '[]',
  points int not null default 1 check (points between 1 and 100),
  tag text,
  created_at timestamptz not null default now()
);

-- Зөв хариулт тусдаа хүснэгтэд. Сурагчид ямар ч policy байхгүй.
create table if not exists public.question_keys (
  question_id uuid primary key references public.questions(id) on delete cascade,
  correct jsonb not null
);

create table if not exists public.exams (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  title text not null,
  description text,
  class_name text,
  duration_min int not null check (duration_min between 1 and 300),
  shuffle_q boolean not null default true,
  shuffle_a boolean not null default true,
  show_answers boolean not null default false,
  status text not null default 'draft' check (status in ('draft','published','closed')),
  created_at timestamptz not null default now()
);

create table if not exists public.exam_questions (
  exam_id uuid not null references public.exams(id) on delete cascade,
  question_id uuid not null references public.questions(id) on delete restrict,
  position int not null default 0,
  primary key (exam_id, question_id)
);

create table if not exists public.exam_codes (
  code text primary key,
  exam_id uuid not null references public.exams(id) on delete cascade,
  created_by uuid default auth.uid(),
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create table if not exists public.exam_access (
  exam_id uuid not null references public.exams(id) on delete cascade,
  student_id uuid not null references public.profiles(id) on delete cascade,
  via_code text,
  created_at timestamptz not null default now(),
  primary key (exam_id, student_id)
);

create table if not exists public.attempts (
  id uuid primary key default gen_random_uuid(),
  exam_id uuid not null references public.exams(id) on delete cascade,
  student_id uuid not null references public.profiles(id) on delete cascade,
  started_at timestamptz not null default now(),
  deadline timestamptz not null,
  submitted_at timestamptz,
  score numeric,
  max_score numeric,
  q_order jsonb not null default '[]',
  o_order jsonb not null default '{}',
  answers jsonb not null default '{}',
  session_token uuid not null default gen_random_uuid(),
  leave_count int not null default 0,
  unique (exam_id, student_id)
);

create table if not exists public.audit_logs (
  id bigserial primary key,
  user_id uuid,
  action text not null,
  detail jsonb not null default '{}',
  created_at timestamptz not null default now()
);
create index if not exists audit_logs_created_idx on public.audit_logs (created_at desc);
create index if not exists attempts_exam_idx on public.attempts (exam_id);

-- ------------------------------------------------------------ ТУСЛАХ ФУНКЦ
create or replace function public.my_role() returns text
language sql stable security definer set search_path = public as $$
  select role from public.profiles where id = auth.uid() and active
$$;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() = 'admin', false)
$$;

create or replace function public.is_teacher() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('teacher','admin'), false)
$$;

create or replace function public._log(p_action text, p_detail jsonb default '{}') returns void
language sql security definer set search_path = public as $$
  insert into public.audit_logs(user_id, action, detail) values (auth.uid(), p_action, coalesce(p_detail,'{}'));
$$;

-- Шинэ хэрэглэгч ҮРГЭЛЖ сурагчаар бүртгэгдэнэ. Багшийн эрхийг зөвхөн админ олгоно.
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles(id, email, full_name, class_name, teacher_requested)
  values (
    new.id, new.email,
    left(coalesce(new.raw_user_meta_data->>'full_name',''), 120),
    nullif(left(btrim(coalesce(new.raw_user_meta_data->>'class_name','')), 40), ''),
    coalesce((new.raw_user_meta_data->>'teacher_requested')::boolean, false)
  );
  insert into public.audit_logs(user_id, action, detail) values (new.id, 'signup', jsonb_build_object('email', new.email));
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- ------------------------------------------------------------ ROW LEVEL SECURITY
alter table public.profiles       enable row level security;
alter table public.questions      enable row level security;
alter table public.question_keys  enable row level security;
alter table public.exams          enable row level security;
alter table public.exam_questions enable row level security;
alter table public.exam_codes     enable row level security;
alter table public.exam_access    enable row level security;
alter table public.attempts       enable row level security;
alter table public.audit_logs     enable row level security;

drop policy if exists p_self on public.profiles;
create policy p_self on public.profiles for select using (id = auth.uid());
drop policy if exists p_staff on public.profiles;
create policy p_staff on public.profiles for select
  using (public.is_admin() or (public.is_teacher() and role = 'student'));
drop policy if exists p_self_update on public.profiles;
create policy p_self_update on public.profiles for update
  using (id = auth.uid()) with check (id = auth.uid());

drop policy if exists q_staff on public.questions;
create policy q_staff on public.questions for all
  using ((owner = auth.uid() and public.is_teacher()) or public.is_admin())
  with check ((owner = auth.uid() and public.is_teacher()) or public.is_admin());

drop policy if exists qk_staff on public.question_keys;
create policy qk_staff on public.question_keys for all
  using (exists (select 1 from public.questions q where q.id = question_id
         and ((q.owner = auth.uid() and public.is_teacher()) or public.is_admin())))
  with check (exists (select 1 from public.questions q where q.id = question_id
         and ((q.owner = auth.uid() and public.is_teacher()) or public.is_admin())));

drop policy if exists e_staff on public.exams;
create policy e_staff on public.exams for all
  using ((owner = auth.uid() and public.is_teacher()) or public.is_admin())
  with check ((owner = auth.uid() and public.is_teacher()) or public.is_admin());

drop policy if exists eq_staff on public.exam_questions;
create policy eq_staff on public.exam_questions for all
  using (exists (select 1 from public.exams e where e.id = exam_id
         and ((e.owner = auth.uid() and public.is_teacher()) or public.is_admin())))
  with check (exists (select 1 from public.exams e where e.id = exam_id
         and ((e.owner = auth.uid() and public.is_teacher()) or public.is_admin())));

drop policy if exists ec_staff on public.exam_codes;
create policy ec_staff on public.exam_codes for all
  using (exists (select 1 from public.exams e where e.id = exam_id
         and ((e.owner = auth.uid() and public.is_teacher()) or public.is_admin())))
  with check (exists (select 1 from public.exams e where e.id = exam_id
         and ((e.owner = auth.uid() and public.is_teacher()) or public.is_admin())));

drop policy if exists ea_self on public.exam_access;
create policy ea_self on public.exam_access for select using (student_id = auth.uid());

drop policy if exists a_self on public.attempts;
create policy a_self on public.attempts for select using (student_id = auth.uid());
drop policy if exists a_staff on public.attempts;
create policy a_staff on public.attempts for select
  using (exists (select 1 from public.exams e where e.id = exam_id
         and ((e.owner = auth.uid() and public.is_teacher()) or public.is_admin())));

drop policy if exists al_admin on public.audit_logs;
create policy al_admin on public.audit_logs for select using (public.is_admin());

-- Хүснэгтийн эрх: бичих үйлдлүүдийг сурагчаас бүрэн хасна.
revoke all on all tables in schema public from anon, authenticated;
revoke all on all sequences in schema public from anon, authenticated;
grant select on public.profiles to authenticated;
grant update (full_name, class_name) on public.profiles to authenticated;
grant select, insert, update, delete on public.questions, public.question_keys,
      public.exams, public.exam_questions, public.exam_codes to authenticated;
grant select on public.exam_access, public.attempts, public.audit_logs to authenticated;

-- ------------------------------------------------------ ШАЛГАЛТЫН ДОТООД ФУНКЦ
-- Асуулт + сонголтууд (зөв хариултгүй), санамсаргүй дарааллаар нь буцаана.
create or replace function public._payload(p_att uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare a public.attempts; res jsonb;
begin
  select * into a from public.attempts where id = p_att;
  select coalesce(jsonb_agg(s.item order by s.ord), '[]'::jsonb) into res from (
    select qo.ord,
      jsonb_build_object('id', q.id, 'type', q.type, 'text', q.text, 'image', q.image, 'points', q.points,
        'options', case when q.type = 'fill' then '[]'::jsonb else coalesce((
            select jsonb_agg(jsonb_build_object('i', oi.v::int, 't', q.options->>(oi.v::int)) order by oi.n)
            from jsonb_array_elements_text(coalesce(a.o_order->(q.id::text), '[]'::jsonb)) with ordinality as oi(v, n)
          ), '[]'::jsonb) end) as item
    from jsonb_array_elements_text(a.q_order) with ordinality as qo(qid, ord)
    join public.questions q on q.id = qo.qid::uuid
  ) s;
  return res;
end $$;

-- Оноог серверт тооцоолно.
create or replace function public._grade(p_att uuid) returns void
language plpgsql security definer set search_path = public as $$
declare a public.attempts; r record; ans jsonb; ok boolean; s numeric := 0; m numeric := 0;
begin
  select * into a from public.attempts where id = p_att for update;
  if a.id is null or a.submitted_at is not null then return; end if;
  for r in
    select q.id, q.type, q.points, k.correct
    from jsonb_array_elements_text(a.q_order) qo(qid)
    join public.questions q on q.id = qo.qid::uuid
    join public.question_keys k on k.question_id = q.id
  loop
    m := m + r.points;
    ans := a.answers -> (r.id::text);
    ok := false;
    if ans is null then continue; end if;
    if r.type in ('single','image') then
      ok := jsonb_typeof(ans) = 'number' and (r.correct -> 0) = ans;
    elsif r.type = 'multi' then
      ok := jsonb_typeof(ans) = 'array'
        and (select count(distinct x) from jsonb_array_elements(ans) x) = jsonb_array_length(r.correct)
        and not exists (select 1 from jsonb_array_elements(ans) x where not (r.correct @> jsonb_build_array(x)));
    elsif r.type = 'fill' then
      ok := jsonb_typeof(ans) = 'string' and exists (
        select 1 from jsonb_array_elements_text(r.correct) c
        where lower(regexp_replace(btrim(c), '\s+', ' ', 'g')) = lower(regexp_replace(btrim(ans #>> '{}'), '\s+', ' ', 'g')));
    end if;
    if ok then s := s + r.points; end if;
  end loop;
  update public.attempts set score = s, max_score = m, submitted_at = least(now(), deadline) where id = p_att;
end $$;

-- Хугацаа дууссан боловч илгээгээгүй оролдлогуудыг автоматаар илгээнэ.
create or replace function public._finalize_overdue() returns void
language plpgsql security definer set search_path = public as $$
declare r record;
begin
  for r in select id, student_id from public.attempts
           where submitted_at is null and deadline + interval '10 seconds' < now() loop
    perform public._grade(r.id);
    insert into public.audit_logs(user_id, action, detail)
      values (r.student_id, 'exam_autosubmit', jsonb_build_object('attempt', r.id));
  end loop;
end $$;

-- --------------------------------------------------------------- СУРАГЧИЙН RPC
create or replace function public.student_env() returns jsonb
language plpgsql security definer set search_path = public as $$
declare me public.profiles;
begin
  select * into me from public.profiles where id = auth.uid() and active;
  if me.id is null or me.role <> 'student' then raise exception 'Зөвхөн сурагчийн эрхтэй'; end if;
  perform public._finalize_overdue();
  return jsonb_build_object(
    'exams', (select coalesce(jsonb_agg(jsonb_build_object(
        'id', e.id, 'title', e.title, 'description', e.description, 'duration_min', e.duration_min,
        'class_name', e.class_name,
        'qcount', (select count(*) from public.exam_questions x where x.exam_id = e.id),
        'teacher', (select full_name from public.profiles where id = e.owner),
        'attempt', (select jsonb_build_object('id', t.id, 'submitted_at', t.submitted_at, 'score', t.score,
                           'max_score', t.max_score, 'deadline', t.deadline)
                    from public.attempts t where t.exam_id = e.id and t.student_id = me.id)
      ) order by e.created_at desc), '[]'::jsonb)
      from public.exams e
      where e.status = 'published'
        and (e.class_name = me.class_name
             or exists (select 1 from public.exam_access a where a.exam_id = e.id and a.student_id = me.id))),
    'history', (select coalesce(jsonb_agg(jsonb_build_object(
        'id', t.id, 'exam_id', t.exam_id, 'title', e.title, 'score', t.score, 'max_score', t.max_score,
        'submitted_at', t.submitted_at, 'show_answers', e.show_answers, 'leave_count', t.leave_count
      ) order by t.submitted_at desc), '[]'::jsonb)
      from public.attempts t join public.exams e on e.id = t.exam_id
      where t.student_id = me.id and t.submitted_at is not null)
  );
end $$;

create or replace function public.join_exam(p_code text) returns uuid
language plpgsql security definer set search_path = public as $$
declare me public.profiles; v_exam uuid; v_exp timestamptz; v_code text := upper(btrim(coalesce(p_code,'')));
begin
  select * into me from public.profiles where id = auth.uid() and active;
  if me.id is null or me.role <> 'student' then raise exception 'Зөвхөн сурагч код ашиглана'; end if;
  select c.exam_id, c.expires_at into v_exam, v_exp
  from public.exam_codes c join public.exams e on e.id = c.exam_id
  where c.code = v_code and e.status = 'published';
  if v_exam is null then raise exception 'Код буруу эсвэл шалгалт нээлттэй биш байна'; end if;
  if v_exp < now() then raise exception 'Кодын хугацаа дууссан байна'; end if;
  insert into public.exam_access(exam_id, student_id, via_code) values (v_exam, me.id, v_code)
    on conflict do nothing;
  perform public._log('code_join', jsonb_build_object('exam', v_exam));
  return v_exam;
end $$;

create or replace function public.start_attempt(p_exam uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare me public.profiles; e public.exams; a public.attempts; v_n int; v_qorder jsonb; v_oorder jsonb;
begin
  select * into me from public.profiles where id = auth.uid() and active;
  if me.id is null or me.role <> 'student' then raise exception 'Зөвхөн сурагч шалгалт өгнө'; end if;
  perform public._finalize_overdue();
  select * into e from public.exams where id = p_exam and status = 'published';
  if e.id is null then raise exception 'Шалгалт нээлттэй биш байна'; end if;
  if not (e.class_name = me.class_name
          or exists (select 1 from public.exam_access x where x.exam_id = e.id and x.student_id = me.id)) then
    raise exception 'Танд энэ шалгалтад орох эрх алга';
  end if;

  select * into a from public.attempts where exam_id = e.id and student_id = me.id;
  if a.id is not null then
    if a.submitted_at is not null then raise exception 'Та энэ шалгалтыг өгч дууссан'; end if;
    -- Давхар нэвтрэлт: шинэ token гаргаж, хуучин самбарыг хүчингүй болгоно.
    update public.attempts set session_token = gen_random_uuid() where id = a.id returning * into a;
    perform public._log('session_takeover', jsonb_build_object('exam', e.id, 'attempt', a.id));
  else
    select count(*) into v_n from public.exam_questions where exam_id = e.id;
    if v_n = 0 then raise exception 'Шалгалтад асуулт алга'; end if;
    select to_jsonb(array_agg(eq.question_id order by case when e.shuffle_q then random() else eq.position end))
      into v_qorder from public.exam_questions eq where eq.exam_id = e.id;
    select coalesce(jsonb_object_agg(q.id::text,
        case when q.type = 'fill' then '[]'::jsonb else (
          select coalesce(jsonb_agg(g order by case when e.shuffle_a then random() else g::double precision end), '[]'::jsonb)
          from generate_series(0, jsonb_array_length(q.options) - 1) g) end), '{}'::jsonb)
      into v_oorder
      from public.exam_questions eq join public.questions q on q.id = eq.question_id where eq.exam_id = e.id;
    insert into public.attempts(exam_id, student_id, deadline, q_order, o_order)
      values (e.id, me.id, now() + make_interval(mins => e.duration_min), v_qorder, v_oorder)
      returning * into a;
    perform public._log('exam_start', jsonb_build_object('exam', e.id, 'attempt', a.id));
  end if;

  return jsonb_build_object(
    'attempt_id', a.id, 'token', a.session_token, 'deadline', a.deadline, 'server_now', now(),
    'exam', jsonb_build_object('id', e.id, 'title', e.title, 'duration_min', e.duration_min),
    'questions', public._payload(a.id), 'answers', a.answers, 'leave_count', a.leave_count);
end $$;

create or replace function public.save_answer(p_attempt uuid, p_token uuid, p_qid uuid, p_value jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare a public.attempts;
begin
  select * into a from public.attempts where id = p_attempt and student_id = auth.uid() for update;
  if a.id is null then raise exception 'Оролдлого олдсонгүй'; end if;
  if a.submitted_at is not null then return jsonb_build_object('ok', false, 'error', 'submitted'); end if;
  if a.session_token <> p_token then
    perform public._log('session_replaced', jsonb_build_object('attempt', a.id));
    return jsonb_build_object('ok', false, 'error', 'session_replaced');
  end if;
  if now() > a.deadline + interval '5 seconds' then return jsonb_build_object('ok', false, 'error', 'expired'); end if;
  if not (a.q_order ? p_qid::text) then raise exception 'Асуулт энэ шалгалтад харьяалагдахгүй'; end if;
  if length(coalesce(p_value::text, '')) > 2000 then raise exception 'Хариулт хэт урт'; end if;
  update public.attempts set answers = answers || jsonb_build_object(p_qid::text, p_value) where id = a.id;
  return jsonb_build_object('ok', true, 'remaining_ms', (extract(epoch from (a.deadline - now())) * 1000)::bigint);
end $$;

create or replace function public.submit_attempt(p_attempt uuid, p_token uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare a public.attempts; e public.exams;
begin
  select * into a from public.attempts where id = p_attempt and student_id = auth.uid();
  if a.id is null then raise exception 'Оролдлого олдсонгүй'; end if;
  if a.submitted_at is null then
    if a.session_token <> p_token and now() <= a.deadline then
      return jsonb_build_object('ok', false, 'error', 'session_replaced');
    end if;
    perform public._grade(a.id);
    perform public._log('exam_submit', jsonb_build_object('attempt', a.id, 'late', now() > a.deadline));
  end if;
  select * into a from public.attempts where id = p_attempt;
  select * into e from public.exams where id = a.exam_id;
  return jsonb_build_object('ok', true, 'score', a.score, 'max_score', a.max_score, 'show_answers', e.show_answers);
end $$;

create or replace function public.log_event(p_attempt uuid, p_event text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if p_event not in ('exam_leave','exam_return') then raise exception 'Буруу үйлдэл'; end if;
  if not exists (select 1 from public.attempts where id = p_attempt and student_id = auth.uid() and submitted_at is null) then
    return;
  end if;
  if p_event = 'exam_leave' then
    update public.attempts set leave_count = leave_count + 1 where id = p_attempt;
  end if;
  perform public._log(p_event, jsonb_build_object('attempt', p_attempt));
end $$;

-- Хариулт харах: ЗӨВХӨН багш зөвшөөрсөн (show_answers) бөгөөд илгээсэн оролдлогод.
create or replace function public.student_review(p_attempt uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare a public.attempts; e public.exams;
begin
  select * into a from public.attempts where id = p_attempt and student_id = auth.uid();
  if a.id is null or a.submitted_at is null then raise exception 'Оролдлого олдсонгүй'; end if;
  select * into e from public.exams where id = a.exam_id;
  if not e.show_answers then raise exception 'Багш хариултыг харуулахыг зөвшөөрөөгүй'; end if;
  return (select coalesce(jsonb_agg(jsonb_build_object(
      'id', q.id, 'type', q.type, 'text', q.text, 'image', q.image, 'options', q.options, 'points', q.points,
      'correct', k.correct, 'answer', a.answers -> (q.id::text)) order by qo.ord), '[]'::jsonb)
    from jsonb_array_elements_text(a.q_order) with ordinality qo(qid, ord)
    join public.questions q on q.id = qo.qid::uuid
    join public.question_keys k on k.question_id = q.id);
end $$;

create or replace function public.log_login() returns void
language sql security definer set search_path = public as $$
  select public._log('login', '{}'::jsonb) where auth.uid() is not null;
$$;

-- ---------------------------------------------------------------- БАГШИЙН RPC
create or replace function public.save_question(p jsonb) returns uuid
language plpgsql security definer set search_path = public as $$
declare v_id uuid; t text; opts jsonb; cor jsonb; n int; pts int;
begin
  if not public.is_teacher() then raise exception 'Эрх хүрэхгүй'; end if;
  t := p->>'type'; opts := coalesce(p->'options', '[]'::jsonb); cor := coalesce(p->'correct', '[]'::jsonb);
  pts := coalesce((p->>'points')::int, 1);
  if t not in ('single','multi','fill','image') then raise exception 'Асуултын төрөл буруу'; end if;
  if btrim(coalesce(p->>'text','')) = '' then raise exception 'Асуултын текст хоосон байна'; end if;
  if pts < 1 or pts > 100 then raise exception 'Оноо 1–100 хооронд байна'; end if;
  if length(coalesce(p->>'image','')) > 600000 then raise exception 'Зураг хэт том байна'; end if;
  if jsonb_typeof(cor) <> 'array' or jsonb_typeof(opts) <> 'array' then raise exception 'Өгөгдөл буруу'; end if;
  if jsonb_array_length(cor) < 1 then raise exception 'Зөв хариулт сонгоно уу'; end if;
  if t = 'fill' then
    opts := '[]'::jsonb;
  else
    n := jsonb_array_length(opts);
    if n < 2 or n > 8 then raise exception 'Сонголт 2–8 байна'; end if;
    if t in ('single','image') and jsonb_array_length(cor) <> 1 then raise exception 'Нэг зөв хариулт сонгоно уу'; end if;
    if exists (select 1 from jsonb_array_elements(cor) x
               where jsonb_typeof(x) <> 'number' or (x #>> '{}')::int < 0 or (x #>> '{}')::int >= n) then
      raise exception 'Зөв хариултын индекс буруу';
    end if;
    if t = 'image' and coalesce(p->>'image','') = '' then raise exception 'Зурагтай асуултад зураг заавал хэрэгтэй'; end if;
  end if;

  v_id := nullif(p->>'id','')::uuid;
  if v_id is null then
    insert into public.questions(owner, type, text, image, options, points, tag)
    values (auth.uid(), t, btrim(p->>'text'), nullif(p->>'image',''), opts, pts, nullif(btrim(coalesce(p->>'tag','')),''))
    returning id into v_id;
  else
    if exists (select 1 from public.exam_questions eq join public.attempts a on a.exam_id = eq.exam_id
               where eq.question_id = v_id) then
      raise exception 'Шалгалтад ашигласан асуултыг засах боломжгүй';
    end if;
    update public.questions set type = t, text = btrim(p->>'text'), image = nullif(p->>'image',''), options = opts,
           points = pts, tag = nullif(btrim(coalesce(p->>'tag','')),'')
     where id = v_id and (owner = auth.uid() or public.is_admin());
    if not found then raise exception 'Асуулт олдсонгүй'; end if;
  end if;
  insert into public.question_keys(question_id, correct) values (v_id, cor)
    on conflict (question_id) do update set correct = excluded.correct;
  return v_id;
end $$;

create or replace function public.save_exam(p jsonb, p_qids uuid[]) returns uuid
language plpgsql security definer set search_path = public as $$
declare v_id uuid; v_owner uuid; v_cnt int;
begin
  if not public.is_teacher() then raise exception 'Эрх хүрэхгүй'; end if;
  if btrim(coalesce(p->>'title','')) = '' then raise exception 'Шалгалтын нэр хоосон байна'; end if;
  if p_qids is null or array_length(p_qids, 1) is null then raise exception 'Дор хаяж 1 асуулт сонгоно уу'; end if;
  v_id := nullif(p->>'id','')::uuid;
  if v_id is null then
    insert into public.exams(owner, title, description, class_name, duration_min, shuffle_q, shuffle_a, show_answers)
    values (auth.uid(), btrim(p->>'title'), nullif(btrim(coalesce(p->>'description','')),''),
            nullif(btrim(coalesce(p->>'class_name','')),''), (p->>'duration_min')::int,
            coalesce((p->>'shuffle_q')::boolean, true), coalesce((p->>'shuffle_a')::boolean, true),
            coalesce((p->>'show_answers')::boolean, false))
    returning id into v_id;
  else
    select owner into v_owner from public.exams where id = v_id;
    if v_owner is null or (v_owner <> auth.uid() and not public.is_admin()) then raise exception 'Эрх хүрэхгүй'; end if;
    if exists (select 1 from public.attempts where exam_id = v_id) then
      raise exception 'Сурагч өгч эхэлсэн шалгалтыг засах боломжгүй';
    end if;
    update public.exams set title = btrim(p->>'title'), description = nullif(btrim(coalesce(p->>'description','')),''),
           class_name = nullif(btrim(coalesce(p->>'class_name','')),''), duration_min = (p->>'duration_min')::int,
           shuffle_q = coalesce((p->>'shuffle_q')::boolean, true), shuffle_a = coalesce((p->>'shuffle_a')::boolean, true),
           show_answers = coalesce((p->>'show_answers')::boolean, false)
     where id = v_id;
    delete from public.exam_questions where exam_id = v_id;
  end if;
  insert into public.exam_questions(exam_id, question_id, position)
    select v_id, t.q, t.ord from unnest(p_qids) with ordinality as t(q, ord)
    where exists (select 1 from public.questions qq where qq.id = t.q and (qq.owner = auth.uid() or public.is_admin()));
  get diagnostics v_cnt = row_count;
  if v_cnt <> array_length(p_qids, 1) then raise exception 'Зарим асуулт олдсонгүй'; end if;
  perform public._log('exam_save', jsonb_build_object('exam', v_id));
  return v_id;
end $$;

create or replace function public.set_exam_status(p_exam uuid, p_status text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if p_status not in ('draft','published','closed') then raise exception 'Төлөв буруу'; end if;
  if not exists (select 1 from public.exams where id = p_exam and ((owner = auth.uid() and public.is_teacher()) or public.is_admin())) then
    raise exception 'Эрх хүрэхгүй';
  end if;
  if p_status = 'published' and not exists (select 1 from public.exam_questions where exam_id = p_exam) then
    raise exception 'Асуултгүй шалгалтыг нийтлэх боломжгүй';
  end if;
  update public.exams set status = p_status where id = p_exam;
  perform public._log('exam_status', jsonb_build_object('exam', p_exam, 'status', p_status));
end $$;

create or replace function public.delete_exam(p_exam uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.exams where id = p_exam and ((owner = auth.uid() and public.is_teacher()) or public.is_admin())) then
    raise exception 'Эрх хүрэхгүй';
  end if;
  delete from public.exams where id = p_exam;
  perform public._log('exam_delete', jsonb_build_object('exam', p_exam));
end $$;

-- Хугацаатай шалгалтын код (6 тэмдэгт).
create or replace function public.make_exam_code(p_exam uuid, p_minutes int) returns jsonb
language plpgsql security definer set search_path = public as $$
declare chars constant text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; v_code text; i int; v_exp timestamptz;
begin
  if not exists (select 1 from public.exams where id = p_exam and ((owner = auth.uid() and public.is_teacher()) or public.is_admin())) then
    raise exception 'Эрх хүрэхгүй';
  end if;
  if p_minutes is null or p_minutes < 1 or p_minutes > 10080 then raise exception 'Хугацаа 1–10080 минут байна'; end if;
  v_exp := now() + make_interval(mins => p_minutes);
  loop
    v_code := '';
    for i in 1..6 loop v_code := v_code || substr(chars, 1 + (get_byte(gen_random_bytes(1), 0) % 32), 1); end loop;
    begin
      insert into public.exam_codes(code, exam_id, expires_at) values (v_code, p_exam, v_exp);
      exit;
    exception when unique_violation then null;
    end;
  end loop;
  perform public._log('code_create', jsonb_build_object('exam', p_exam, 'minutes', p_minutes));
  return jsonb_build_object('code', v_code, 'expires_at', v_exp);
end $$;

create or replace function public.teacher_results(p_exam uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.exams where id = p_exam and ((owner = auth.uid() and public.is_teacher()) or public.is_admin())) then
    raise exception 'Эрх хүрэхгүй';
  end if;
  perform public._finalize_overdue();
  return (select coalesce(jsonb_agg(jsonb_build_object(
      'student_id', p.id, 'full_name', p.full_name, 'class_name', p.class_name, 'email', p.email,
      'score', a.score, 'max_score', a.max_score, 'started_at', a.started_at,
      'submitted_at', a.submitted_at, 'leave_count', a.leave_count) order by p.full_name), '[]'::jsonb)
    from public.attempts a join public.profiles p on p.id = a.student_id where a.exam_id = p_exam);
end $$;

create or replace function public.teacher_overview() returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_teacher() then raise exception 'Эрх хүрэхгүй'; end if;
  perform public._finalize_overdue();
  return (
    with mine as (
      select a.* from public.attempts a join public.exams e on e.id = a.exam_id
      where e.owner = auth.uid() and a.submitted_at is not null)
    select jsonb_build_object(
      'students', (select count(*) from public.profiles where role = 'student' and active),
      'exams', (select count(*) from public.exams where owner = auth.uid()),
      'attempted', (select count(distinct student_id) from mine),
      'avg', (select round(avg(score / nullif(max_score, 0) * 100)::numeric, 1) from mine),
      'per_exam', (select coalesce(jsonb_agg(x), '[]'::jsonb) from (
          select e.id, e.title, count(m.id) as n, round(avg(m.score / nullif(m.max_score, 0) * 100)::numeric, 1) as avg_pct
          from public.exams e left join mine m on m.exam_id = e.id
          where e.owner = auth.uid() and e.status <> 'draft'
          group by e.id order by e.created_at desc limit 10) x),
      'dist', (select jsonb_agg(d.cnt order by d.b) from (
          select g.b, count(m.id) as cnt from generate_series(0, 9) g(b)
          left join mine m on least(floor(m.score / nullif(m.max_score, 0) * 10)::int, 9) = g.b
          group by g.b) d)
    )
  );
end $$;

create or replace function public.teacher_students() returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_teacher() then raise exception 'Эрх хүрэхгүй'; end if;
  return (select coalesce(jsonb_agg(jsonb_build_object(
      'id', p.id, 'full_name', p.full_name, 'email', p.email, 'class_name', p.class_name,
      'exams', coalesce(s.n, 0), 'avg', s.a) order by p.class_name, p.full_name), '[]'::jsonb)
    from public.profiles p
    left join (
      select t.student_id, count(*) n, round(avg(t.score / nullif(t.max_score, 0) * 100)::numeric, 1) a
      from public.attempts t join public.exams e on e.id = t.exam_id
      where e.owner = auth.uid() and t.submitted_at is not null group by t.student_id) s on s.student_id = p.id
    where p.role = 'student' and p.active);
end $$;

create or replace function public.class_names() returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_teacher() then raise exception 'Эрх хүрэхгүй'; end if;
  return (select coalesce(jsonb_agg(c order by c), '[]'::jsonb)
          from (select distinct class_name as c from public.profiles
                where role = 'student' and active and class_name is not null) x);
end $$;

-- Чансаа: сурагч зөвхөн өөрийн анги, багш хүссэн анги.
create or replace function public.leaderboard(p_class text default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare me public.profiles; v_class text;
begin
  select * into me from public.profiles where id = auth.uid() and active;
  if me.id is null then raise exception 'Нэвтрээгүй байна'; end if;
  perform public._finalize_overdue();
  v_class := case when me.role = 'student' then me.class_name else nullif(btrim(coalesce(p_class,'')), '') end;
  if me.role = 'student' and v_class is null then return '[]'::jsonb; end if;
  return (select coalesce(jsonb_agg(r order by r.avg desc, r.exams desc), '[]'::jsonb) from (
      select p.id as student_id, p.full_name, p.class_name, count(a.id) as exams,
             round(avg(a.score / nullif(a.max_score, 0) * 100)::numeric, 1) as avg
      from public.profiles p join public.attempts a on a.student_id = p.id and a.submitted_at is not null
      where p.role = 'student' and p.active and (v_class is null or p.class_name = v_class)
      group by p.id, p.full_name, p.class_name
      order by avg desc, exams desc limit 100) r);
end $$;

-- ---------------------------------------------------------------- АДМИН RPC
create or replace function public.admin_users() returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Зөвхөн админ'; end if;
  return (select coalesce(jsonb_agg(to_jsonb(p) order by p.created_at desc), '[]'::jsonb) from public.profiles p);
end $$;

create or replace function public.admin_set_role(p_user uuid, p_role text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Зөвхөн админ'; end if;
  if p_role not in ('student','teacher','admin') then raise exception 'Эрх буруу'; end if;
  if p_user = auth.uid() then raise exception 'Өөрийн эрхийг өөрчлөх боломжгүй'; end if;
  update public.profiles set role = p_role, teacher_requested = false where id = p_user;
  perform public._log('role_change', jsonb_build_object('user', p_user, 'role', p_role));
end $$;

create or replace function public.admin_set_active(p_user uuid, p_active boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Зөвхөн админ'; end if;
  if p_user = auth.uid() then raise exception 'Өөрийн бүртгэлийг хаах боломжгүй'; end if;
  update public.profiles set active = p_active where id = p_user;
  perform public._log('user_active', jsonb_build_object('user', p_user, 'active', p_active));
end $$;

create or replace function public.admin_stats() returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Зөвхөн админ'; end if;
  perform public._finalize_overdue();
  return jsonb_build_object(
    'students', (select count(*) from public.profiles where role = 'student'),
    'teachers', (select count(*) from public.profiles where role = 'teacher'),
    'admins', (select count(*) from public.profiles where role = 'admin'),
    'pending', (select count(*) from public.profiles where teacher_requested and role = 'student'),
    'exams_draft', (select count(*) from public.exams where status = 'draft'),
    'exams_published', (select count(*) from public.exams where status = 'published'),
    'exams_closed', (select count(*) from public.exams where status = 'closed'),
    'questions', (select count(*) from public.questions),
    'attempts', (select count(*) from public.attempts),
    'submitted', (select count(*) from public.attempts where submitted_at is not null),
    'avg', (select round(avg(score / nullif(max_score, 0) * 100)::numeric, 1) from public.attempts where submitted_at is not null),
    'events_24h', (select count(*) from public.audit_logs where created_at > now() - interval '24 hours')
  );
end $$;

create or replace function public.admin_exams() returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Зөвхөн админ'; end if;
  return (select coalesce(jsonb_agg(jsonb_build_object(
      'id', e.id, 'title', e.title, 'status', e.status, 'class_name', e.class_name, 'created_at', e.created_at,
      'owner', (select full_name from public.profiles where id = e.owner),
      'attempts', (select count(*) from public.attempts where exam_id = e.id)) order by e.created_at desc), '[]'::jsonb)
    from public.exams e);
end $$;

create or replace function public.admin_audit(p_limit int default 200) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Зөвхөн админ'; end if;
  return (select coalesce(jsonb_agg(jsonb_build_object(
      'id', l.id, 'action', l.action, 'detail', l.detail, 'created_at', l.created_at,
      'user', coalesce((select full_name from public.profiles where id = l.user_id), '—')) order by l.id desc), '[]'::jsonb)
    from (select * from public.audit_logs order by id desc limit least(greatest(p_limit, 1), 500)) l);
end $$;

-- ----------------------------------------------------- ФУНКЦИЙН ЭРХИЙН ТОХИРГОО
revoke execute on all functions in schema public from public, anon, authenticated;
alter default privileges in schema public revoke execute on functions from public, anon, authenticated;

grant execute on function
  public.my_role(), public.is_admin(), public.is_teacher(),
  public.student_env(), public.join_exam(text), public.start_attempt(uuid),
  public.save_answer(uuid, uuid, uuid, jsonb), public.submit_attempt(uuid, uuid),
  public.log_event(uuid, text), public.student_review(uuid), public.log_login(),
  public.save_question(jsonb), public.save_exam(jsonb, uuid[]), public.set_exam_status(uuid, text),
  public.delete_exam(uuid), public.make_exam_code(uuid, int), public.teacher_results(uuid),
  public.teacher_overview(), public.teacher_students(), public.class_names(), public.leaderboard(text),
  public.admin_users(), public.admin_set_role(uuid, text), public.admin_set_active(uuid, boolean),
  public.admin_stats(), public.admin_exams(), public.admin_audit(int)
to authenticated;

-- ============================================================================
-- ЭХНИЙ АДМИНЫГ ҮҮСГЭХ: апп-аар бүртгүүлсний дараа (эсвэл Authentication → Users
-- дотор хэрэглэгч үүсгээд) өөрийн имэйлээр доорх мөрийг ажиллуулна:
--   update public.profiles set role = 'admin' where email = 'ТАНЫ@ИМЭЙЛ';
-- Үүний дараа Админ самбараас багшийн хүсэлтийг батлана.
-- ============================================================================
<!doctype html><html lang="mn"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>SHALGALT</title>
<meta name="claude:viewport-fit-sides" content="cover">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Manrope:wght@600;700;800&display=swap" rel="stylesheet">
<style>
/* Layout: ХЭЛХЭЭ sidebar + агуулгын талбар (desktop), гар утсан дээр drawer sidebar + дээд мөр.
   Нэг л харагдах ертөнц: гүн navy дэвсгэр, electric blue өргөлт, шилэн (glass) гадаргуу. */
:root{
  --bg:#060b1d; --bg-2:#0a1330; --panel:rgba(16,27,58,.62); --panel-2:rgba(24,38,78,.55);
  --solid:#0d1735; --line:rgba(120,160,255,.16); --line-2:rgba(120,160,255,.28);
  --fg:#e9efff; --mute:#93a3cc; --faint:#62729c;
  --blue:#2f6bff; --blue-2:#5b8cff; --cyan:#37d0ff;
  --good:#2fd9a0; --warn:#ffb648; --bad:#ff5f78;
  --font-display:'Manrope','Inter',system-ui,sans-serif;
  --font-body:'Inter',system-ui,'Segoe UI',Roboto,sans-serif;
  --r:16px;
  color-scheme:dark;
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg);color:var(--fg);font:14.5px/1.55 var(--font-body);-webkit-font-smoothing:antialiased;min-height:100vh;overflow-x:hidden}
body::before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;
  background:radial-gradient(900px 520px at 88% -8%,rgba(47,107,255,.30),transparent 62%),
  radial-gradient(700px 480px at -8% 28%,rgba(55,208,255,.10),transparent 60%),
  linear-gradient(180deg,var(--bg-2),var(--bg) 62%)}
h1,h2,h3,h4{font-family:var(--font-display);margin:0;letter-spacing:-.01em;text-wrap:balance}
h1{font-size:clamp(28px,5vw,46px);line-height:1.08;font-weight:800}
h2{font-size:clamp(21px,3vw,28px);font-weight:800}
h3{font-size:16px;font-weight:700}
p{margin:0}
a{color:var(--blue-2)}
button,input,select,textarea{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
.ic{flex:none;vertical-align:-3px}
.mute{color:var(--mute)} .faint{color:var(--faint)} .good{color:var(--good)} .bad{color:var(--bad)} .warn{color:var(--warn)}
.num{font-variant-numeric:tabular-nums}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.between{justify-content:space-between}
.grow{flex:1;min-width:0}
.stack{display:flex;flex-direction:column;gap:14px}
.grid{display:grid;gap:16px}
.g4{grid-template-columns:repeat(auto-fit,minmax(200px,1fr))}
.g3{grid-template-columns:repeat(auto-fit,minmax(min(100%,280px),1fr))}
.g2{grid-template-columns:repeat(auto-fit,minmax(min(100%,380px),1fr))}

/* gutters */
.gut{padding-left:max(16px,env(safe-area-inset-left,0px));padding-right:max(16px,env(safe-area-inset-right,0px))}

/* glass */
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:20px;
  backdrop-filter:blur(16px) saturate(1.2);-webkit-backdrop-filter:blur(16px) saturate(1.2);
  box-shadow:0 1px 0 rgba(255,255,255,.05) inset,0 18px 40px -22px rgba(0,0,0,.6);min-width:0}
.card.pad0{padding:0;overflow:hidden}
.card-h{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px;flex-wrap:wrap}
.card-h h3{display:flex;gap:8px;align-items:center}

/* buttons */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:1px solid var(--line-2);background:rgba(255,255,255,.04);
  color:var(--fg);padding:10px 16px;border-radius:12px;font-weight:600;cursor:pointer;transition:transform .15s,background .2s,box-shadow .2s,border-color .2s;text-decoration:none;min-height:42px;white-space:nowrap}
.btn:hover{background:rgba(255,255,255,.09);border-color:var(--blue-2)}
.btn:active{transform:scale(.98)}
.btn.primary{background:linear-gradient(135deg,var(--blue),#1f4fe0);border-color:transparent;box-shadow:0 10px 28px -10px rgba(47,107,255,.85)}
.btn.primary:hover{box-shadow:0 14px 34px -10px rgba(47,107,255,1);filter:brightness(1.08)}
.btn.danger{border-color:rgba(255,95,120,.45);color:#ff9aab}
.btn.danger:hover{background:rgba(255,95,120,.12);border-color:var(--bad)}
.btn.ghost{border-color:transparent;background:transparent;color:var(--mute)}
.btn.ghost:hover{color:var(--fg);background:rgba(255,255,255,.06)}
.btn.sm{padding:6px 11px;min-height:34px;font-size:13px;border-radius:10px}
.btn.lg{padding:14px 24px;min-height:50px;font-size:15.5px;border-radius:14px}
.btn[disabled]{opacity:.5;pointer-events:none}
.icon-btn{width:40px;height:40px;padding:0}

/* forms */
label.f{display:flex;flex-direction:column;gap:6px;font-size:13px;color:var(--mute);font-weight:500;min-width:0}
.in,select.in,textarea.in{width:100%;background:rgba(6,11,29,.7);border:1px solid var(--line-2);border-radius:12px;padding:11px 13px;color:var(--fg);min-height:44px;transition:border-color .2s,box-shadow .2s}
textarea.in{resize:vertical;min-height:90px}
.in:focus{outline:none;border-color:var(--blue-2);box-shadow:0 0 0 3px rgba(91,140,255,.25)}
select.in option{background:var(--solid)}
.chk{display:flex;gap:10px;align-items:center;cursor:pointer;color:var(--fg);font-size:14px}
.chk input{width:18px;height:18px;accent-color:var(--blue)}
.formgrid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(min(100%,220px),1fr))}

/* badges */
.badge{display:inline-flex;align-items:center;gap:5px;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid var(--line-2);color:var(--mute);background:rgba(255,255,255,.04);white-space:nowrap}
.badge.blue{color:#9db9ff;border-color:rgba(91,140,255,.5);background:rgba(47,107,255,.14)}
.badge.good{color:var(--good);border-color:rgba(47,217,160,.4);background:rgba(47,217,160,.1)}
.badge.warn{color:var(--warn);border-color:rgba(255,182,72,.4);background:rgba(255,182,72,.1)}
.badge.bad{color:var(--bad);border-color:rgba(255,95,120,.4);background:rgba(255,95,120,.1)}

/* tables */
.tw{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{width:100%;border-collapse:collapse;min-width:560px}
th{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--faint);text-align:left;padding:12px 16px;font-weight:600;border-bottom:1px solid var(--line)}
td{padding:12px 16px;border-bottom:1px solid var(--line);vertical-align:middle}
tr:last-child td{border-bottom:0}
tbody tr{transition:background .15s}
tbody tr:hover{background:rgba(91,140,255,.06)}
td.r,th.r{text-align:right}

/* stat */
.stat{display:flex;gap:14px;align-items:center}
.stat .chip{width:46px;height:46px;border-radius:14px;display:grid;place-items:center;background:linear-gradient(135deg,rgba(47,107,255,.35),rgba(55,208,255,.14));border:1px solid var(--line-2);color:#bcd0ff;flex:none}
.stat .v{font:800 28px/1.1 var(--font-display);font-variant-numeric:tabular-nums}
.stat .l{color:var(--mute);font-size:13px}

/* progress */
.bar{height:8px;border-radius:99px;background:rgba(255,255,255,.08);overflow:hidden}
.bar>i{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--blue),var(--cyan));transition:width .5s}

/* shell */
.shell{display:grid;grid-template-columns:268px minmax(0,1fr);min-height:100vh}
.side{position:sticky;top:0;height:100vh;padding:20px 14px;padding-left:max(14px,env(safe-area-inset-left,0px));display:flex;flex-direction:column;gap:18px;background:rgba(7,12,32,.78);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);border-right:1px solid var(--line);overflow-y:auto}
.nav{display:flex;flex-direction:column;gap:4px}
.nav a{display:flex;align-items:center;gap:12px;padding:11px 14px;border-radius:12px;color:var(--mute);text-decoration:none;font-weight:500;transition:background .2s,color .2s}
.nav a:hover{background:rgba(255,255,255,.05);color:var(--fg)}
.nav a.on{background:linear-gradient(90deg,rgba(47,107,255,.32),rgba(47,107,255,.08));color:#fff;box-shadow:inset 2px 0 0 var(--blue-2)}
.nav .sec{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint);padding:12px 14px 4px}
.me{margin-top:auto;display:flex;gap:10px;align-items:center;padding:10px;border-radius:14px;background:var(--panel-2);border:1px solid var(--line)}
.av{width:38px;height:38px;border-radius:12px;background:linear-gradient(135deg,var(--blue),var(--cyan));display:grid;place-items:center;font:800 14px var(--font-display);color:#04102e;flex:none}
.av.lg{width:64px;height:64px;border-radius:20px;font-size:22px}
.topbar{display:none}
.side-x{display:none}
.scrim{display:none}
.main{min-width:0}
.page{padding-top:28px;padding-bottom:64px;padding-left:max(16px,env(safe-area-inset-left,0px));padding-right:max(16px,env(safe-area-inset-right,0px));max-width:1200px;margin:0 auto}
.page-h{display:flex;justify-content:space-between;align-items:flex-end;gap:14px;flex-wrap:wrap;margin-bottom:22px}
.page-h p{color:var(--mute);margin-top:4px}
@media(max-width:899px){
  .shell{display:block}
  .side{position:fixed;inset:0 auto 0 0;width:min(86vw,300px);height:100%;transform:translateX(-104%);transition:transform .28s cubic-bezier(.2,.8,.2,1);z-index:60;background:rgba(7,12,32,.96)}
  .side.open{transform:none}
  .scrim.open{display:block;position:fixed;inset:0;background:rgba(2,6,20,.6);z-index:50;animation:fade .2s}
  .topbar{display:flex;align-items:center;justify-content:space-between;gap:10px;position:sticky;top:env(safe-area-inset-top,0px);z-index:40;padding-top:10px;padding-bottom:10px;padding-left:max(16px,env(safe-area-inset-left,0px));padding-right:max(16px,env(safe-area-inset-right,0px));background:rgba(7,12,32,.82);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-bottom:1px solid var(--line)}
  .page{padding-top:20px}
  .side-x{display:inline-flex}
}

/* logo */
.logo{display:flex;align-items:center;gap:10px;font:800 19px var(--font-display);letter-spacing:.14em;color:#fff;text-decoration:none}
.logo svg{filter:drop-shadow(0 6px 14px rgba(47,107,255,.6))}

/* landing */
.land{max-width:1180px;margin:0 auto;padding-left:max(16px,env(safe-area-inset-left,0px));padding-right:max(16px,env(safe-area-inset-right,0px))}
.l-nav{display:flex;align-items:center;justify-content:space-between;padding-block:20px;gap:12px;flex-wrap:wrap}
.hero{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(0,.95fr);gap:40px;align-items:center;padding-block:40px 64px}
.hero h1 em{font-style:normal;background:linear-gradient(90deg,#7aa2ff,var(--cyan));-webkit-background-clip:text;background-clip:text;color:transparent}
.hero .lead{font-size:17px;color:var(--mute);margin:18px 0 28px;max-width:52ch}
@media(max-width:860px){.hero{grid-template-columns:1fr;padding-block:20px 40px}}
.sample{position:relative;padding:22px}
.sample .opt{display:flex;gap:12px;align-items:center;padding:12px 14px;border:1px solid var(--line-2);border-radius:12px;margin-top:10px;background:rgba(6,11,29,.5)}
.sample .opt .k{width:26px;height:26px;border-radius:8px;display:grid;place-items:center;background:rgba(255,255,255,.06);font-weight:700;font-size:12px}
.sample .opt.sel{border-color:var(--blue-2);background:rgba(47,107,255,.18);animation:pick 6s infinite}
.ring{position:relative;width:64px;height:64px}
.ring svg{transform:rotate(-90deg)}
.ring circle.t{stroke:rgba(255,255,255,.1)}
.ring circle.p{stroke:var(--cyan);stroke-linecap:round;stroke-dasharray:176;animation:count 30s linear infinite}
.ring b{position:absolute;inset:0;display:grid;place-items:center;font:700 14px var(--font-display)}
.feat{padding:22px;transition:transform .25s,border-color .25s}
.feat:hover{transform:translateY(-3px);border-color:var(--line-2)}
.feat .chip{width:44px;height:44px;border-radius:13px;display:grid;place-items:center;background:rgba(47,107,255,.18);border:1px solid var(--line-2);color:#a9c1ff;margin-bottom:14px}
.feat p{color:var(--mute);margin-top:6px;font-size:14px}
.sect{padding-block:36px}
.sect>h2{margin-bottom:8px}
.steps{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,240px),1fr));gap:16px;counter-reset:s}
.steps .card{position:relative;padding-top:52px}
.steps .card::before{counter-increment:s;content:counter(s);position:absolute;top:16px;left:20px;width:28px;height:28px;border-radius:9px;background:var(--blue);display:grid;place-items:center;font:800 13px var(--font-display)}
.foot{border-top:1px solid var(--line);padding-block:26px;color:var(--faint);font-size:13px;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}

/* auth */
.authwrap{min-height:100vh;display:grid;place-items:center;padding:24px max(16px,env(safe-area-inset-left,0px))}
.authcard{width:min(440px,100%)}
.tabs{display:flex;gap:4px;padding:4px;border-radius:12px;background:rgba(6,11,29,.7);border:1px solid var(--line);margin-bottom:18px}
.tabs button{flex:1;border:0;background:transparent;padding:9px;border-radius:9px;color:var(--mute);font-weight:600;cursor:pointer}
.tabs button.on{background:var(--blue);color:#fff}
.notice{display:flex;gap:10px;padding:12px 14px;border-radius:12px;border:1px solid rgba(255,182,72,.35);background:rgba(255,182,72,.08);color:#ffd9a0;font-size:13px}
.notice.info{border-color:rgba(91,140,255,.4);background:rgba(47,107,255,.1);color:#b9ccff}
.notice.bad{border-color:rgba(255,95,120,.4);background:rgba(255,95,120,.1);color:#ffb3c0}

/* modal + toast */
.modal-b{position:fixed;inset:0;z-index:100;background:rgba(2,6,20,.7);backdrop-filter:blur(4px);display:grid;place-items:center;padding:16px;animation:fade .2s;overflow-y:auto}
.modal{width:min(720px,100%);max-height:calc(100vh - 32px);overflow-y:auto;background:var(--solid);border:1px solid var(--line-2);border-radius:20px;padding:22px;animation:pop .25s cubic-bezier(.2,.9,.3,1.2);box-shadow:0 30px 80px -20px rgba(0,0,0,.8)}
.modal.sm{width:min(440px,100%)}
.modal-h{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:16px}
.toasts{position:fixed;z-index:200;right:max(16px,env(safe-area-inset-right,0px));bottom:max(16px,env(safe-area-inset-bottom,0px));display:flex;flex-direction:column;gap:8px;max-width:min(380px,calc(100vw - 32px))}
.toast{padding:12px 16px;border-radius:12px;background:var(--solid);border:1px solid var(--line-2);box-shadow:0 14px 30px -10px rgba(0,0,0,.7);animation:pop .25s;display:flex;gap:10px;align-items:center}
.toast.good{border-color:rgba(47,217,160,.5)} .toast.bad{border-color:rgba(255,95,120,.55)}

.empty{text-align:center;padding:38px 16px;color:var(--mute)}
.empty .chip{width:56px;height:56px;border-radius:18px;margin:0 auto 14px;display:grid;place-items:center;background:rgba(47,107,255,.15);border:1px solid var(--line-2);color:#a9c1ff}
.empty h3{color:var(--fg);margin-bottom:4px}
.empty .row{justify-content:center;margin-top:16px}
.spin{width:28px;height:28px;border-radius:50%;border:3px solid var(--line-2);border-top-color:var(--cyan);animation:rot .8s linear infinite;margin:60px auto}

/* charts */
.chart{width:100%;height:auto;display:block;overflow:visible}
.chart text{fill:var(--mute);font:11px var(--font-body)}
.chart .grid{stroke:rgba(120,160,255,.14);stroke-width:1}
.chart .val{fill:var(--fg);font-weight:600}

/* question bank / exam */
.qrow{display:flex;gap:12px;align-items:flex-start;padding:14px 16px;border-bottom:1px solid var(--line)}
.qrow:last-child{border-bottom:0}
.qrow .qt{flex:1;min-width:0;word-break:break-word}
.optrow{display:flex;gap:8px;align-items:center}
.optrow input[type=radio],.optrow input[type=checkbox]{width:20px;height:20px;accent-color:var(--good);flex:none}
.thumb{max-width:100%;max-height:220px;border-radius:12px;border:1px solid var(--line-2);display:block}
.pick{display:flex;gap:12px;align-items:center;padding:11px 14px;border-bottom:1px solid var(--line);cursor:pointer}
.pick:last-child{border-bottom:0}
.pick:hover{background:rgba(91,140,255,.06)}
.pick input{width:18px;height:18px;accent-color:var(--blue);flex:none}
.scroll{max-height:360px;overflow-y:auto}
.codebox{font:800 34px var(--font-display);letter-spacing:.3em;text-align:center;padding:18px;border:1px dashed var(--blue-2);border-radius:16px;background:rgba(47,107,255,.1);user-select:all}

.exam{min-height:100vh;display:flex;flex-direction:column}
.exam-top{position:sticky;top:env(safe-area-inset-top,0px);z-index:30;display:flex;align-items:center;justify-content:space-between;gap:12px;padding-block:12px;padding-left:max(16px,env(safe-area-inset-left,0px));padding-right:max(16px,env(safe-area-inset-right,0px));background:rgba(7,12,32,.88);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-bottom:1px solid var(--line)}
.timer{font:800 20px var(--font-display);font-variant-numeric:tabular-nums;padding:6px 14px;border-radius:12px;background:rgba(47,107,255,.18);border:1px solid var(--line-2);display:flex;gap:8px;align-items:center}
.timer.low{background:rgba(255,95,120,.18);border-color:rgba(255,95,120,.6);color:#ffb3c0;animation:pulse 1s infinite}
.exam-body{flex:1;display:grid;grid-template-columns:minmax(0,1fr) 270px;gap:18px;max-width:1100px;width:100%;margin:0 auto;padding-top:22px;padding-bottom:40px;padding-left:max(16px,env(safe-area-inset-left,0px));padding-right:max(16px,env(safe-area-inset-right,0px))}
@media(max-width:860px){.exam-body{grid-template-columns:1fr}.qnav-card{order:-1}}
.ans{display:flex;gap:12px;align-items:center;padding:14px 16px;border:1px solid var(--line-2);border-radius:14px;margin-top:10px;cursor:pointer;background:rgba(6,11,29,.5);transition:border-color .2s,background .2s,transform .15s;width:100%;text-align:left;color:var(--fg)}
.ans:hover{border-color:var(--blue-2)}
.ans.sel{border-color:var(--blue-2);background:rgba(47,107,255,.22)}
.ans .k{width:28px;height:28px;border-radius:9px;display:grid;place-items:center;background:rgba(255,255,255,.07);font-weight:700;font-size:12px;flex:none}
.ans.sel .k{background:var(--blue);color:#fff}
.ans.ok{border-color:var(--good);background:rgba(47,217,160,.12)}
.ans.no{border-color:var(--bad);background:rgba(255,95,120,.12)}
.qgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(40px,1fr));gap:8px}
.qgrid button{height:40px;border-radius:10px;border:1px solid var(--line-2);background:transparent;color:var(--mute);font-weight:700;cursor:pointer}
.qgrid button.done{background:rgba(47,107,255,.25);color:#fff;border-color:var(--blue-2)}
.qgrid button.cur{outline:2px solid var(--cyan);outline-offset:1px}
.savestate{font-size:12px;color:var(--faint);display:flex;gap:6px;align-items:center}
.savestate.ok{color:var(--good)} .savestate.err{color:var(--warn)}
.scorering{width:150px;height:150px;margin:0 auto}
.lb-1{background:linear-gradient(90deg,rgba(255,200,60,.14),transparent)}
.lb-2{background:linear-gradient(90deg,rgba(190,205,230,.12),transparent)}
.lb-3{background:linear-gradient(90deg,rgba(220,140,90,.12),transparent)}
.rank{width:30px;height:30px;border-radius:10px;display:inline-grid;place-items:center;background:rgba(255,255,255,.07);font-weight:800;font-size:13px}
.ach{display:flex;gap:12px;align-items:center;padding:10px 0}
.ach .chip{width:40px;height:40px;border-radius:12px;display:grid;place-items:center;border:1px solid var(--line-2);background:rgba(255,255,255,.04);color:var(--faint)}
.ach.on .chip{background:linear-gradient(135deg,var(--blue),var(--cyan));color:#04102e;border-color:transparent}
.ach:not(.on){opacity:.65}
textarea.csv{font:12px/1.5 ui-monospace,Menlo,monospace;min-height:200px;white-space:pre}

@keyframes fade{from{opacity:0}to{opacity:1}}
@keyframes pop{from{opacity:0;transform:translateY(10px) scale(.97)}to{opacity:1;transform:none}}
@keyframes rise{from{opacity:.55;transform:translateY(10px)}to{opacity:1;transform:none}}
@keyframes rot{to{transform:rotate(360deg)}}
@keyframes pulse{50%{opacity:.7}}
@keyframes count{from{stroke-dashoffset:0}to{stroke-dashoffset:176}}
@keyframes pick{0%,35%{border-color:var(--line-2);background:rgba(6,11,29,.5)}45%,100%{border-color:var(--blue-2);background:rgba(47,107,255,.18)}}
.rise>*{animation:rise .5s both}
.rise>*:nth-child(2){animation-delay:.05s}.rise>*:nth-child(3){animation-delay:.1s}.rise>*:nth-child(4){animation-delay:.15s}.rise>*:nth-child(5){animation-delay:.2s}.rise>*:nth-child(6){animation-delay:.25s}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style>
</head><body><div id="app"></div>
<div class="toasts" id="toasts"></div>
<div id="modal-root"></div>
<script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.45.4/dist/umd/supabase.min.js"></script>
<script>
/* ===================== SHALGALT: core ===================== */
// Supabase холбох бол энд URL болон anon key-ээ бичнэ (README-г үзнэ үү).
// Хоосон үлдээвэл туршилтын горим: өгөгдөл зөвхөн энэ хөтөч дээр хадгалагдана.
const CONFIG = { SUPABASE_URL: "", SUPABASE_ANON_KEY: "" };

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const p2 = n => String(n).padStart(2, '0');
const fmtDate = iso => { if (!iso) return '—'; const d = new Date(iso); return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}`; };
const pct = (s, m) => (m ? Math.round((s / m) * 1000) / 10 : 0);
const initials = n => (String(n || '?').trim().split(/\s+/).slice(0, 2).map(w => w[0]).join('') || '?').toUpperCase();
const uid = () => (crypto.randomUUID ? crypto.randomUUID() : 'id' + Math.random().toString(16).slice(2) + Date.now());
const shuffle = a => { a = [...a]; for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1));[a[i], a[j]] = [a[j], a[i]]; } return a; };
const LETTERS = 'АБВГДЕЖЗ';

const ICONS = {
  home: '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>',
  file: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/><path d="M9 13h6M9 17h6"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  db: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c0-3.6 2.9-6 6.5-6s6.5 2.4 6.5 6"/><path d="M16 4.5a3.5 3.5 0 0 1 0 7M18 14.5c2 .7 3.5 2.5 3.5 5.5"/>',
  trophy: '<path d="M8 21h8M12 17v4M7 4h10v5a5 5 0 0 1-10 0z"/><path d="M7 6H4v2a3 3 0 0 0 3 3M17 6h3v2a3 3 0 0 1-3 3"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  download: '<path d="M12 3v12M7 10l5 5 5-5M4 20h16"/>',
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-7 8-7s8 3 8 7"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
  x: '<path d="M6 6l12 12M18 6L6 18"/>',
  chart: '<path d="M4 20V10M10 20V4M16 20v-8M22 20H2"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/>',
  timer: '<circle cx="12" cy="13" r="8"/><path d="M12 9v4l2 2M9 2h6"/>',
  check: '<path d="M5 12l5 5 9-10"/>',
  trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
  edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/>',
  image: '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="1.7"/><path d="M21 16l-5-5-9 9"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h8"/>',
  log: '<path d="M5 4h14v16H5z"/><path d="M8 9h8M8 13h8M8 17h5"/>',
  star: '<path d="M12 3l2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1L3.2 9.5l6.1-.9z"/>',
  eye: '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
  shuffle: '<path d="M3 7h4l10 10h4M3 17h4l3-3M14 10l3-3h4"/><path d="M18 4l3 3-3 3M18 14l3 3-3 3"/>',
  alert: '<path d="M12 4l10 17H2z"/><path d="M12 10v5M12 18v.5"/>',
  play: '<path d="M7 4l13 8-13 8z"/>',
  save: '<path d="M5 3h12l4 4v14H5z"/><path d="M8 3v6h8V3M8 21v-7h8v7"/>',
  cpu: '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.5M3 12h.5M3 18h.5"/>',
  back: '<path d="M15 5l-7 7 7 7"/>',
  next: '<path d="M9 5l7 7-7 7"/>',
};
const ic = (n, s = 18) => `<svg class="ic" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n] || ''}</svg>`;
const logoSvg = (s = 32) => `<svg width="${s}" height="${s}" viewBox="0 0 40 40" aria-hidden="true"><defs><linearGradient id="lg${s}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#5b8cff"/><stop offset="1" stop-color="#1f4fe0"/></linearGradient></defs><rect width="40" height="40" rx="12" fill="url(#lg${s})"/><path d="M26.5 13.5c-1.4-1.6-3.6-2.5-6.2-2.5-3.5 0-6 1.8-6 4.6 0 2.6 1.9 3.8 5.5 4.6 2.6.6 3.3 1 3.3 1.9 0 1-1 1.7-2.7 1.7-1.7 0-3.2-.7-4.4-2l-2.3 2.6c1.6 1.8 4 2.9 6.7 2.9 3.7 0 6.2-1.9 6.2-4.9 0-2.6-1.8-3.8-5.4-4.6-2.6-.6-3.4-1-3.4-1.8 0-.8.8-1.4 2.2-1.4 1.3 0 2.5.5 3.5 1.5z" fill="#fff"/></svg>`;
const logo = (href = '#/') => `<a class="logo" href="${href}">${logoSvg(32)}<span>SHALGALT</span></a>`;

/* ---------- toast + modal ---------- */
function toast(msg, kind = '') {
  const el = document.createElement('div');
  el.className = 'toast ' + kind;
  el.setAttribute('role', 'status');
  el.innerHTML = `${ic(kind === 'bad' ? 'alert' : 'check')}<span>${esc(msg)}</span>`;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), kind === 'bad' ? 6000 : 3200);
}
function openModal(html, cls = '') {
  $('#modal-root').innerHTML = `<div class="modal-b" data-act="modalBg"><div class="modal ${cls}" role="dialog" aria-modal="true">${html}</div></div>`;
}
function closeModal() { $('#modal-root').innerHTML = ''; }
const modalHead = t => `<div class="modal-h"><h3>${t}</h3><button class="btn ghost icon-btn" data-act="closeModal" aria-label="Хаах">${ic('x')}</button></div>`;
function confirmModal(title, text, okLabel, onOk, danger = true) {
  ACT._confirm = async () => { closeModal(); await onOk(); };
  openModal(`${modalHead(esc(title))}<p class="mute">${esc(text)}</p><div class="row" style="margin-top:20px;justify-content:flex-end"><button class="btn" data-act="closeModal">Болих</button><button class="btn ${danger ? 'danger' : 'primary'}" data-act="_confirm">${esc(okLabel)}</button></div>`, 'sm');
}

/* ---------- misc UI blocks ---------- */
const empty = (icon, title, text, actions = '') => `<div class="empty"><div class="chip">${ic(icon, 26)}</div><h3>${esc(title)}</h3><p>${esc(text)}</p>${actions ? `<div class="row">${actions}</div>` : ''}</div>`;
const statCard = (icon, value, label) => `<div class="card stat"><div class="chip">${ic(icon, 22)}</div><div><div class="v">${value}</div><div class="l">${esc(label)}</div></div></div>`;
const spinner = () => '<div class="spin" role="status" aria-label="Ачаалж байна"></div>';
const scoreBadge = p => `<span class="badge ${p >= 80 ? 'good' : p >= 50 ? 'blue' : 'bad'} num">${p}%</span>`;

/* ---------- SVG charts (theme tokens) ---------- */
function barChart(items, { max = 100, suffix = '%', h = 200 } = {}) {
  if (!items.length) return '';
  const W = 600, L = 34, B = 34, T = 18, ch = h - B - T, n = items.length, bw = Math.min(56, (W - L - 10) / n * .62), step = (W - L - 10) / n;
  const id = 'bg' + Math.random().toString(36).slice(2, 7);
  let s = `<svg class="chart" viewBox="0 0 ${W} ${h}" role="img"><defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#5b8cff"/><stop offset="1" stop-color="#2f6bff" stop-opacity=".55"/></linearGradient></defs>`;
  [0, .25, .5, .75, 1].forEach(f => { const y = T + ch - ch * f; s += `<line class="grid" x1="${L}" x2="${W}" y1="${y}" y2="${y}"/><text x="${L - 6}" y="${y + 4}" text-anchor="end">${Math.round(max * f)}</text>`; });
  items.forEach((it, i) => {
    const v = Math.max(0, Math.min(max, it.value ?? 0)), bh = ch * v / max, x = L + step * i + (step - bw) / 2, y = T + ch - bh;
    s += `<rect x="${x}" y="${y}" width="${bw}" height="${Math.max(bh, 0)}" rx="6" fill="url(#${id})"><title>${esc(it.label)}: ${it.value ?? '—'}${suffix}</title></rect>`;
    s += `<text class="val" x="${x + bw / 2}" y="${y - 5}" text-anchor="middle">${it.value == null ? '—' : it.value + (suffix === '%' ? '%' : '')}</text>`;
    const lab = String(it.label); s += `<text x="${x + bw / 2}" y="${h - 14}" text-anchor="middle">${esc(lab.length > 9 ? lab.slice(0, 8) + '…' : lab)}</text>`;
  });
  return s + '</svg>';
}
function lineChart(pts, { h = 200 } = {}) {
  if (!pts.length) return '';
  const W = 600, L = 34, B = 30, T = 16, R = 14, cw = W - L - R, ch = h - B - T, id = 'lc' + Math.random().toString(36).slice(2, 7);
  const X = i => L + (pts.length === 1 ? cw / 2 : cw * i / (pts.length - 1)), Y = v => T + ch - ch * v / 100;
  let s = `<svg class="chart" viewBox="0 0 ${W} ${h}" role="img"><defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#37d0ff" stop-opacity=".35"/><stop offset="1" stop-color="#37d0ff" stop-opacity="0"/></linearGradient></defs>`;
  [0, 25, 50, 75, 100].forEach(f => { s += `<line class="grid" x1="${L}" x2="${W - R}" y1="${Y(f)}" y2="${Y(f)}"/><text x="${L - 6}" y="${Y(f) + 4}" text-anchor="end">${f}</text>`; });
  const path = pts.map((p, i) => `${i ? 'L' : 'M'}${X(i)} ${Y(p.value)}`).join(' ');
  if (pts.length > 1) s += `<path d="${path} L${X(pts.length - 1)} ${Y(0)} L${X(0)} ${Y(0)}Z" fill="url(#${id})"/>`;
  s += `<path d="${path}" fill="none" stroke="#37d0ff" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>`;
  pts.forEach((p, i) => {
    const last = i === pts.length - 1;
    s += `<circle cx="${X(i)}" cy="${Y(p.value)}" r="${last ? 6 : 4}" fill="${last ? '#37d0ff' : '#0d1735'}" stroke="#37d0ff" stroke-width="2"><title>${esc(p.label)}: ${p.value}%</title></circle>`;
    if (last || pts.length <= 6) s += `<text class="val" x="${X(i)}" y="${Y(p.value) - 11}" text-anchor="middle">${p.value}%</text>`;
    if (pts.length <= 8 || i % Math.ceil(pts.length / 8) === 0) { const lab = String(p.label); s += `<text x="${X(i)}" y="${h - 10}" text-anchor="middle">${esc(lab.length > 9 ? lab.slice(0, 8) + '…' : lab)}</text>`; }
  });
  return s + '</svg>';
}
function ringChart(value, size = 150) {
  const r = 58, c = 2 * Math.PI * r, off = c * (1 - value / 100), id = 'rg' + Math.random().toString(36).slice(2, 7);
  const col = value >= 80 ? '#2fd9a0' : value >= 50 ? '#5b8cff' : '#ff5f78';
  return `<svg class="scorering" viewBox="0 0 140 140" width="${size}" height="${size}" role="img" aria-label="${value}%"><circle cx="70" cy="70" r="${r}" fill="none" stroke="rgba(255,255,255,.1)" stroke-width="12"/><circle cx="70" cy="70" r="${r}" fill="none" stroke="${col}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${off}" transform="rotate(-90 70 70)"/><text x="70" y="78" text-anchor="middle" style="font:800 28px Manrope,sans-serif;fill:#e9efff">${value}%</text></svg>`;
}

/* ---------- CSV export ---------- */
const csvCell = v => { let s = String(v ?? ''); if (/^[=+\-@]/.test(s)) s = "'" + s; return /[",\n;]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
function showCSV(filename, header, rows) {
  const csv = [header, ...rows].map(r => r.map(csvCell).join(',')).join('\r\n');
  window.__csv = { filename, csv };
  openModal(`${modalHead('Үр дүн экспортлох')}<p class="mute" style="margin-bottom:12px">${rows.length} мөр · CSV (Excel-д нээхэд Монгол үсэг зөв харагдана)</p><textarea class="in csv" readonly id="csvbox">${esc(csv)}</textarea><div class="row" style="margin-top:14px;justify-content:flex-end"><button class="btn" data-act="csvCopy">${ic('copy')} Хуулах</button><button class="btn primary" data-act="csvDownload">${ic('download')} Файл татах</button></div>`);
}

/* ---------- action registry + events ---------- */
const ACT = {};
document.addEventListener('click', e => {
  const el = e.target.closest('[data-act]');
  if (!el) return;
  const name = el.dataset.act;
  if (name === 'modalBg') { if (e.target === el) closeModal(); return; }
  const fn = ACT[name];
  if (!fn) return;
  e.preventDefault();
  if (el.dataset.busy) return;
  el.dataset.busy = '1';
  Promise.resolve().then(() => fn(el, e)).catch(err => { console.error(err); toast(err.message || 'Алдаа гарлаа', 'bad'); }).finally(() => { delete el.dataset.busy; });
});
document.addEventListener('submit', e => {
  const f = e.target.closest('[data-form]');
  if (!f) return;
  e.preventDefault();
  const fn = ACT[f.dataset.form];
  if (!fn || f.dataset.busy) return;
  f.dataset.busy = '1';
  const btn = $('button[type=submit]', f); if (btn) btn.disabled = true;
  Promise.resolve().then(() => fn(f, e)).catch(err => { console.error(err); toast(err.message || 'Алдаа гарлаа', 'bad'); }).finally(() => { delete f.dataset.busy; if (btn) btn.disabled = false; });
});
document.addEventListener('keydown', e => { if (e.key === 'Escape' && $('#modal-root').children.length && !window.RUN) closeModal(); });
ACT.closeModal = closeModal;
ACT.csvCopy = async () => {
  const box = $('#csvbox');
  try { await navigator.clipboard.writeText(window.__csv.csv); toast('Хууллаа', 'good'); }
  catch (e) { box.focus(); box.select(); toast('Текстийг сонгосон, Ctrl+C дарна уу'); }
};
ACT.csvDownload = () => {
  const { filename, csv } = window.__csv;
  try {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8' }));
    a.download = filename; document.body.appendChild(a); a.click(); a.remove();
    toast('Татах хүсэлт илгээлээ. Татагдахгүй бол "Хуулах" товчийг ашиглана уу.');
  } catch (e) { toast('Татаж чадсангүй, "Хуулах" товчийг ашиглана уу', 'bad'); }
};

/* ---------- image resize (зурагтай асуулт) ---------- */
function fileToDataUrl(file, maxW = 720) {
  return new Promise((res, rej) => {
    if (!/^image\/(png|jpe?g|webp|gif)$/.test(file.type)) return rej(new Error('Зөвхөн PNG, JPG, WEBP зураг'));
    const fr = new FileReader();
    fr.onerror = () => rej(new Error('Файл уншиж чадсангүй'));
    fr.onload = () => {
      const img = new Image();
      img.onerror = () => rej(new Error('Зураг буруу байна'));
      img.onload = () => {
        const k = Math.min(1, maxW / img.width), c = document.createElement('canvas');
        c.width = Math.round(img.width * k); c.height = Math.round(img.height * k);
        c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
        res(c.toDataURL('image/jpeg', .78));
      };
      img.src = fr.result;
    };
    fr.readAsDataURL(file);
  });
}

const ACTION_LABELS = {
  signup: 'Бүртгүүлсэн', login: 'Нэвтэрсэн', exam_start: 'Шалгалт эхэлсэн', exam_submit: 'Шалгалт илгээсэн',
  exam_autosubmit: 'Хугацаа дуусч автоматаар илгээгдсэн', session_takeover: 'Давхар нэвтрэлт (шинэ сессээр үргэлжлүүлсэн)',
  session_replaced: 'Хуучин сессээс хариулт оролдсон', exam_leave: 'Шалгалтаас гарсан', exam_return: 'Шалгалт руу буцсан',
  code_join: 'Кодоор орсон', code_create: 'Шалгалтын код үүсгэсэн', role_change: 'Эрх өөрчилсөн', user_active: 'Бүртгэл идэвхжүүлсэн/хаасан',
  exam_status: 'Шалгалтын төлөв өөрчилсөн', exam_delete: 'Шалгалт устгасан', exam_save: 'Шалгалт хадгалсан',
};
const ROLE_LABELS = { student: 'Сурагч', teacher: 'Багш', admin: 'Админ' };
const STATUS_LABELS = { draft: ['Ноорог', ''], published: ['Нээлттэй', 'good'], closed: ['Хаагдсан', 'warn'] };
/* ===================== Туршилтын горим: өгөгдөл хөтөч дээр ===================== */
/* Энэ адаптер schema.sql-ийн серверийн логикийг (оноо тооцоо, зөв хариулт нуух, код, токен) дуурайна.
   Бодит хамгаалалт БИШ — зөвхөн Supabase горимд сервер хамгаална. */
function localAPI() {
  const KEY = 'shalgalt_demo_v1', SESS = 'shalgalt_demo_session';
  let mem = null, memSess = null;
  const nowISO = () => new Date().toISOString();
  const seed = () => ({
    users: [{ id: uid(), email: 'admin@shalgalt.mn', pw: 'Admin12345', full_name: 'Системийн админ', role: 'admin', class_name: null, active: true, teacher_requested: false, created_at: nowISO() }],
    questions: [], exams: [], codes: [], access: [], attempts: [], audit: [],
  });
  const db = () => {
    if (mem) return mem;
    try { mem = JSON.parse(localStorage.getItem(KEY)); } catch (e) { mem = null; }
    if (!mem || !mem.users) mem = seed();
    return mem;
  };
  const save = () => { try { localStorage.setItem(KEY, JSON.stringify(mem)); } catch (e) { /* санах ой л ашиглана */ } };
  const getSess = () => { try { return sessionStorage.getItem(SESS); } catch (e) { return memSess; } };
  const setSess = v => { memSess = v; try { v ? sessionStorage.setItem(SESS, v) : sessionStorage.removeItem(SESS); } catch (e) { /* */ } };
  const err = m => { throw new Error(m); };
  const pub = u => u && { id: u.id, email: u.email, full_name: u.full_name, class_name: u.class_name, role: u.role, active: u.active, teacher_requested: u.teacher_requested, created_at: u.created_at };
  const log = (action, detail = {}, user = getSess()) => { const d = db(); d.audit.push({ id: d.audit.length + 1, user_id: user, action, detail, created_at: nowISO() }); };
  const me = () => { const u = db().users.find(x => x.id === getSess() && x.active); if (!u) err('Нэвтрээгүй эсвэл бүртгэл идэвхгүй байна'); return u; };
  const need = (...roles) => { const u = me(); if (!roles.includes(u.role)) err('Эрх хүрэхгүй'); return u; };
  const isStaff = u => u.role === 'teacher' || u.role === 'admin';
  const ownsExam = (u, e) => e && ((e.owner === u.id && isStaff(u)) || u.role === 'admin');
  const nameOf = id => (db().users.find(x => x.id === id) || {}).full_name || '—';
  const clean = s => String(s ?? '').trim().replace(/\s+/g, ' ').toLowerCase();

  function grade(a) {
    if (a.submitted_at) return;
    const d = db(); let s = 0, m = 0;
    a.q_order.forEach(qid => {
      const q = d.questions.find(x => x.id === qid); if (!q) return;
      m += q.points; const ans = a.answers[qid]; if (ans == null) return;
      let ok = false;
      if (q.type === 'single' || q.type === 'image') ok = typeof ans === 'number' && ans === q.correct[0];
      else if (q.type === 'multi') { const set = new Set(Array.isArray(ans) ? ans : []); ok = Array.isArray(ans) && set.size === q.correct.length && [...set].every(x => q.correct.includes(x)); }
      else if (q.type === 'fill') ok = typeof ans === 'string' && q.correct.some(c => clean(c) === clean(ans));
      if (ok) s += q.points;
    });
    a.score = s; a.max_score = m;
    a.submitted_at = new Date(Math.min(Date.now(), new Date(a.deadline).getTime())).toISOString();
  }
  function finalize() {
    const d = db(); let ch = false;
    d.attempts.forEach(a => { if (!a.submitted_at && new Date(a.deadline).getTime() + 10000 < Date.now()) { grade(a); log('exam_autosubmit', { attempt: a.id }, a.student_id); ch = true; } });
    if (ch) save();
  }
  const accessible = (u, e) => e.status === 'published' && (e.class_name && e.class_name === u.class_name || db().access.some(a => a.exam_id === e.id && a.student_id === u.id));
  const avgOf = list => list.length ? Math.round(list.reduce((s, a) => s + pct(a.score, a.max_score), 0) / list.length * 10) / 10 : null;
  const done = () => db().attempts.filter(a => a.submitted_at);

  return {
    mode: 'local',
    async init() { const u = db().users.find(x => x.id === getSess() && x.active); return pub(u) || null; },
    async signIn(email, pw) {
      const u = db().users.find(x => x.email === String(email).trim().toLowerCase());
      if (!u || u.pw !== pw) err('Имэйл эсвэл нууц үг буруу байна');
      if (!u.active) err('Бүртгэл түр хаагдсан байна. Админтай холбогдоно уу');
      setSess(u.id); log('login'); save(); return pub(u);
    },
    async signUp({ email, pw, name, className, wantTeacher }) {
      email = String(email).trim().toLowerCase();
      if (!/^\S+@\S+\.\S+$/.test(email)) err('Имэйл хаяг буруу байна');
      if (String(pw).length < 8) err('Нууц үг хамгийн багадаа 8 тэмдэгт байна');
      if (!String(name).trim()) err('Нэрээ оруулна уу');
      const d = db(); if (d.users.some(u => u.email === email)) err('Энэ имэйл бүртгэлтэй байна');
      const u = { id: uid(), email, pw, full_name: String(name).trim().slice(0, 120), role: 'student', class_name: String(className || '').trim().slice(0, 40) || null, active: true, teacher_requested: !!wantTeacher, created_at: nowISO() };
      d.users.push(u); log('signup', { email }, u.id); setSess(u.id); save(); return pub(u);
    },
    async signOut() { setSess(null); },
    async updateProfile({ full_name, class_name }) {
      const u = me(); if (!String(full_name).trim()) err('Нэр хоосон байна');
      u.full_name = String(full_name).trim().slice(0, 120); u.class_name = String(class_name || '').trim().slice(0, 40) || null; save(); return pub(u);
    },

    /* ---- багш ---- */
    async tOverview() {
      const u = need('teacher', 'admin'); finalize(); const d = db();
      const mine = d.attempts.filter(a => a.submitted_at && ownsExamId(u, a.exam_id, d));
      const exams = d.exams.filter(e => e.owner === u.id);
      const dist = Array(10).fill(0); mine.forEach(a => { dist[Math.min(9, Math.floor(a.score / a.max_score * 10))]++; });
      return {
        students: d.users.filter(x => x.role === 'student' && x.active).length, exams: exams.length,
        attempted: new Set(mine.map(a => a.student_id)).size, avg: avgOf(mine),
        per_exam: exams.filter(e => e.status !== 'draft').slice(-10).reverse().map(e => { const l = mine.filter(a => a.exam_id === e.id); return { id: e.id, title: e.title, n: l.length, avg_pct: avgOf(l) }; }),
        dist,
      };
    },
    async tStudents() {
      const u = need('teacher', 'admin'); const d = db();
      return d.users.filter(x => x.role === 'student' && x.active).sort((a, b) => (a.class_name || '').localeCompare(b.class_name || '') || a.full_name.localeCompare(b.full_name))
        .map(s => { const l = done().filter(a => a.student_id === s.id && ownsExamId(u, a.exam_id, d)); return { id: s.id, full_name: s.full_name, email: s.email, class_name: s.class_name, exams: l.length, avg: avgOf(l) }; });
    },
    async classNames() { need('teacher', 'admin'); return [...new Set(db().users.filter(x => x.role === 'student' && x.active && x.class_name).map(x => x.class_name))].sort(); },
    async listQuestions() { const u = need('teacher', 'admin'); return db().questions.filter(q => q.owner === u.id || u.role === 'admin').slice().reverse().map(q => ({ ...q })); },
    async saveQuestion(p) {
      const u = need('teacher', 'admin'), d = db(); const t = p.type; let opts = p.options || [], cor = p.correct || [];
      if (!['single', 'multi', 'fill', 'image'].includes(t)) err('Асуултын төрөл буруу');
      if (!String(p.text || '').trim()) err('Асуултын текст хоосон байна');
      const pts = Number(p.points || 1); if (!(pts >= 1 && pts <= 100)) err('Оноо 1–100 хооронд байна');
      if ((p.image || '').length > 600000) err('Зураг хэт том байна');
      if (!cor.length) err('Зөв хариулт сонгоно уу');
      if (t === 'fill') { opts = []; cor = cor.map(x => String(x).trim()).filter(Boolean); if (!cor.length) err('Зөв хариулт сонгоно уу'); }
      else {
        opts = opts.map(x => String(x).trim()); if (opts.length < 2 || opts.length > 8) err('Сонголт 2–8 байна');
        if (opts.some(x => !x)) err('Хоосон сонголт байна');
        if ((t === 'single' || t === 'image') && cor.length !== 1) err('Нэг зөв хариулт сонгоно уу');
        if (cor.some(i => !Number.isInteger(i) || i < 0 || i >= opts.length)) err('Зөв хариултын индекс буруу');
        if (t === 'image' && !p.image) err('Зурагтай асуултад зураг заавал хэрэгтэй');
      }
      const rec = { type: t, text: String(p.text).trim(), image: p.image || null, options: opts, points: pts, tag: String(p.tag || '').trim() || null, correct: cor };
      if (p.id) {
        const q = d.questions.find(x => x.id === p.id && (x.owner === u.id || u.role === 'admin')); if (!q) err('Асуулт олдсонгүй');
        const used = d.exams.some(e => e.qids.includes(q.id) && d.attempts.some(a => a.exam_id === e.id));
        if (used) err('Шалгалтад ашигласан асуултыг засах боломжгүй');
        Object.assign(q, rec); save(); return q.id;
      }
      const q = { id: uid(), owner: u.id, created_at: nowISO(), ...rec }; d.questions.push(q); save(); return q.id;
    },
    async deleteQuestion(id) {
      const u = need('teacher', 'admin'), d = db(); const q = d.questions.find(x => x.id === id && (x.owner === u.id || u.role === 'admin')); if (!q) err('Асуулт олдсонгүй');
      if (d.exams.some(e => e.qids.includes(id))) err('Асуулт шалгалтад ашиглагдаж байна. Эхлээд шалгалтаас хасна уу');
      d.questions = d.questions.filter(x => x.id !== id); save();
    },
    async listExams() {
      const u = need('teacher', 'admin'), d = db(); finalize();
      return d.exams.filter(e => e.owner === u.id || u.role === 'admin').slice().reverse().map(e => ({
        ...e, qids: [...e.qids], attempts: d.attempts.filter(a => a.exam_id === e.id).length,
        codes: d.codes.filter(c => c.exam_id === e.id).map(c => ({ ...c })).sort((a, b) => b.expires_at.localeCompare(a.expires_at)),
      }));
    },
    async saveExam(p, qids) {
      const u = need('teacher', 'admin'), d = db();
      if (!String(p.title || '').trim()) err('Шалгалтын нэр хоосон байна');
      if (!qids.length) err('Дор хаяж 1 асуулт сонгоно уу');
      const dur = Number(p.duration_min); if (!(dur >= 1 && dur <= 300)) err('Хугацаа 1–300 минут байна');
      if (qids.some(id => !d.questions.find(q => q.id === id && (q.owner === u.id || u.role === 'admin')))) err('Зарим асуулт олдсонгүй');
      const rec = { title: String(p.title).trim(), description: String(p.description || '').trim() || null, class_name: String(p.class_name || '').trim() || null, duration_min: dur, shuffle_q: !!p.shuffle_q, shuffle_a: !!p.shuffle_a, show_answers: !!p.show_answers, qids: [...qids] };
      if (p.id) {
        const e = d.exams.find(x => x.id === p.id); if (!ownsExam(u, e)) err('Эрх хүрэхгүй');
        if (d.attempts.some(a => a.exam_id === e.id)) err('Сурагч өгч эхэлсэн шалгалтыг засах боломжгүй');
        Object.assign(e, rec); log('exam_save', { exam: e.id }); save(); return e.id;
      }
      const e = { id: uid(), owner: u.id, status: 'draft', created_at: nowISO(), ...rec }; d.exams.push(e); log('exam_save', { exam: e.id }); save(); return e.id;
    },
    async setReveal(id, v) { const u = need('teacher', 'admin'); const e = db().exams.find(x => x.id === id); if (!ownsExam(u, e)) err('Эрх хүрэхгүй'); e.show_answers = !!v; save(); },
    async setExamStatus(id, st) {
      const u = need('teacher', 'admin'), e = db().exams.find(x => x.id === id); if (!ownsExam(u, e)) err('Эрх хүрэхгүй');
      if (st === 'published' && !e.qids.length) err('Асуултгүй шалгалтыг нийтлэх боломжгүй');
      e.status = st; log('exam_status', { exam: id, status: st }); save();
    },
    async deleteExam(id) {
      const u = need('teacher', 'admin'), d = db(), e = d.exams.find(x => x.id === id); if (!ownsExam(u, e)) err('Эрх хүрэхгүй');
      d.exams = d.exams.filter(x => x.id !== id); d.attempts = d.attempts.filter(a => a.exam_id !== id); d.codes = d.codes.filter(c => c.exam_id !== id); d.access = d.access.filter(a => a.exam_id !== id);
      log('exam_delete', { exam: id }); save();
    },
    async makeCode(examId, minutes) {
      const u = need('teacher', 'admin'), d = db(), e = d.exams.find(x => x.id === examId); if (!ownsExam(u, e)) err('Эрх хүрэхгүй');
      minutes = Number(minutes); if (!(minutes >= 1 && minutes <= 10080)) err('Хугацаа 1–10080 минут байна');
      const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; let code;
      do { const b = crypto.getRandomValues(new Uint8Array(6)); code = [...b].map(x => chars[x % 32]).join(''); } while (d.codes.some(c => c.code === code));
      const expires_at = new Date(Date.now() + minutes * 60000).toISOString();
      d.codes.push({ code, exam_id: examId, expires_at, created_at: nowISO() }); log('code_create', { exam: examId, minutes }); save(); return { code, expires_at };
    },
    async examResults(examId) {
      const u = need('teacher', 'admin'), d = db(); const e = d.exams.find(x => x.id === examId); if (!ownsExam(u, e)) err('Эрх хүрэхгүй'); finalize();
      return d.attempts.filter(a => a.exam_id === examId).map(a => { const s = d.users.find(x => x.id === a.student_id) || {}; return { student_id: a.student_id, full_name: s.full_name, class_name: s.class_name, email: s.email, score: a.score, max_score: a.max_score, started_at: a.started_at, submitted_at: a.submitted_at, leave_count: a.leave_count }; }).sort((a, b) => String(a.full_name).localeCompare(String(b.full_name)));
    },
    async leaderboard(cls) {
      const u = me(); finalize(); const d = db(); let c = u.role === 'student' ? u.class_name : (cls || null);
      if (u.role === 'student' && !c) return [];
      const by = {}; done().forEach(a => { (by[a.student_id] = by[a.student_id] || []).push(a); });
      return Object.entries(by).map(([id, l]) => { const s = d.users.find(x => x.id === id); return s && s.role === 'student' && s.active && (!c || s.class_name === c) ? { student_id: id, full_name: s.full_name, class_name: s.class_name, exams: l.length, avg: avgOf(l) } : null; }).filter(Boolean).sort((a, b) => b.avg - a.avg || b.exams - a.exams).slice(0, 100);
    },

    /* ---- сурагч ---- */
    async studentEnv() {
      const u = need('student'); finalize(); const d = db();
      return {
        exams: d.exams.filter(e => accessible(u, e)).slice().reverse().map(e => { const a = d.attempts.find(x => x.exam_id === e.id && x.student_id === u.id); return { id: e.id, title: e.title, description: e.description, duration_min: e.duration_min, class_name: e.class_name, qcount: e.qids.length, teacher: nameOf(e.owner), attempt: a ? { id: a.id, submitted_at: a.submitted_at, score: a.score, max_score: a.max_score, deadline: a.deadline } : null }; }),
        history: d.attempts.filter(a => a.student_id === u.id && a.submitted_at).sort((a, b) => b.submitted_at.localeCompare(a.submitted_at)).map(a => { const e = d.exams.find(x => x.id === a.exam_id) || {}; return { id: a.id, exam_id: a.exam_id, title: e.title, score: a.score, max_score: a.max_score, submitted_at: a.submitted_at, show_answers: !!e.show_answers, leave_count: a.leave_count }; }),
      };
    },
    async joinCode(code) {
      const u = need('student'), d = db(); code = String(code || '').trim().toUpperCase();
      const c = d.codes.find(x => x.code === code); const e = c && d.exams.find(x => x.id === c.exam_id);
      if (!c || !e || e.status !== 'published') err('Код буруу эсвэл шалгалт нээлттэй биш байна');
      if (new Date(c.expires_at) < new Date()) err('Кодын хугацаа дууссан байна');
      if (!d.access.some(a => a.exam_id === e.id && a.student_id === u.id)) d.access.push({ exam_id: e.id, student_id: u.id, via_code: code });
      log('code_join', { exam: e.id }); save(); return e.id;
    },
    async startAttempt(examId) {
      const u = need('student'), d = db(); finalize();
      const e = d.exams.find(x => x.id === examId && x.status === 'published'); if (!e) err('Шалгалт нээлттэй биш байна');
      if (!accessible(u, e)) err('Танд энэ шалгалтад орох эрх алга');
      let a = d.attempts.find(x => x.exam_id === e.id && x.student_id === u.id);
      if (a) {
        if (a.submitted_at) err('Та энэ шалгалтыг өгч дууссан');
        a.session_token = uid(); log('session_takeover', { exam: e.id, attempt: a.id });
      } else {
        if (!e.qids.length) err('Шалгалтад асуулт алга');
        const q_order = e.shuffle_q ? shuffle(e.qids) : [...e.qids], o_order = {};
        e.qids.forEach(id => { const q = d.questions.find(x => x.id === id); o_order[id] = q.type === 'fill' ? [] : (e.shuffle_a ? shuffle(q.options.map((_, i) => i)) : q.options.map((_, i) => i)); });
        a = { id: uid(), exam_id: e.id, student_id: u.id, started_at: nowISO(), deadline: new Date(Date.now() + e.duration_min * 60000).toISOString(), submitted_at: null, score: null, max_score: null, q_order, o_order, answers: {}, session_token: uid(), leave_count: 0 };
        d.attempts.push(a); log('exam_start', { exam: e.id, attempt: a.id });
      }
      save();
      return {
        attempt_id: a.id, token: a.session_token, deadline: a.deadline, server_now: nowISO(), leave_count: a.leave_count, answers: { ...a.answers },
        exam: { id: e.id, title: e.title, duration_min: e.duration_min },
        questions: a.q_order.map(id => { const q = d.questions.find(x => x.id === id); return { id: q.id, type: q.type, text: q.text, image: q.image, points: q.points, options: q.type === 'fill' ? [] : a.o_order[id].map(i => ({ i, t: q.options[i] })) }; }),
      };
    },
    async saveAnswer(attId, token, qid, value) {
      const u = need('student'), a = db().attempts.find(x => x.id === attId && x.student_id === u.id); if (!a) err('Оролдлого олдсонгүй');
      if (a.submitted_at) return { ok: false, error: 'submitted' };
      if (a.session_token !== token) { log('session_replaced', { attempt: a.id }); save(); return { ok: false, error: 'session_replaced' }; }
      if (Date.now() > new Date(a.deadline).getTime() + 5000) return { ok: false, error: 'expired' };
      if (!a.q_order.includes(qid)) err('Асуулт энэ шалгалтад харьяалагдахгүй');
      if (JSON.stringify(value).length > 2000) err('Хариулт хэт урт');
      a.answers[qid] = value; save(); return { ok: true };
    },
    async submit(attId, token) {
      const u = need('student'), d = db(), a = d.attempts.find(x => x.id === attId && x.student_id === u.id); if (!a) err('Оролдлого олдсонгүй');
      if (!a.submitted_at) {
        if (a.session_token !== token && Date.now() <= new Date(a.deadline).getTime()) return { ok: false, error: 'session_replaced' };
        grade(a); log('exam_submit', { attempt: a.id, late: Date.now() > new Date(a.deadline).getTime() }); save();
      }
      const e = d.exams.find(x => x.id === a.exam_id); return { ok: true, score: a.score, max_score: a.max_score, show_answers: !!e.show_answers };
    },
    async logEvent(attId, ev) {
      const u = need('student'), a = db().attempts.find(x => x.id === attId && x.student_id === u.id && !x.submitted_at); if (!a) return;
      if (!['exam_leave', 'exam_return'].includes(ev)) err('Буруу үйлдэл');
      if (ev === 'exam_leave') a.leave_count++; log(ev, { attempt: a.id }); save();
    },
    async review(attId) {
      const u = need('student'), d = db(), a = d.attempts.find(x => x.id === attId && x.student_id === u.id); if (!a || !a.submitted_at) err('Оролдлого олдсонгүй');
      const e = d.exams.find(x => x.id === a.exam_id); if (!e.show_answers) err('Багш хариултыг харуулахыг зөвшөөрөөгүй');
      return a.q_order.map(id => { const q = d.questions.find(x => x.id === id); return { id, type: q.type, text: q.text, image: q.image, options: q.options, points: q.points, correct: q.correct, answer: a.answers[id] ?? null }; });
    },

    /* ---- админ ---- */
    async adminUsers() { need('admin'); return db().users.slice().reverse().map(pub); },
    async adminSetRole(id, role) {
      const u = need('admin'); if (id === u.id) err('Өөрийн эрхийг өөрчлөх боломжгүй'); if (!ROLE_LABELS[role]) err('Эрх буруу');
      const t = db().users.find(x => x.id === id); if (!t) err('Хэрэглэгч олдсонгүй'); t.role = role; t.teacher_requested = false; log('role_change', { user: id, role }); save();
    },
    async adminSetActive(id, v) {
      const u = need('admin'); if (id === u.id) err('Өөрийн бүртгэлийг хаах боломжгүй');
      const t = db().users.find(x => x.id === id); if (!t) err('Хэрэглэгч олдсонгүй'); t.active = !!v; log('user_active', { user: id, active: !!v }); save();
    },
    async adminStats() {
      need('admin'); finalize(); const d = db(), c = r => d.users.filter(u => u.role === r).length, ex = s => d.exams.filter(e => e.status === s).length;
      return { students: c('student'), teachers: c('teacher'), admins: c('admin'), pending: d.users.filter(u => u.teacher_requested && u.role === 'student').length, exams_draft: ex('draft'), exams_published: ex('published'), exams_closed: ex('closed'), questions: d.questions.length, attempts: d.attempts.length, submitted: done().length, avg: avgOf(done()), events_24h: d.audit.filter(a => Date.now() - new Date(a.created_at) < 864e5).length };
    },
    async adminExams() { need('admin'); const d = db(); return d.exams.slice().reverse().map(e => ({ id: e.id, title: e.title, status: e.status, class_name: e.class_name, created_at: e.created_at, owner: nameOf(e.owner), attempts: d.attempts.filter(a => a.exam_id === e.id).length })); },
    async adminAudit() { need('admin'); return db().audit.slice(-200).reverse().map(l => ({ ...l, user: nameOf(l.user_id) })); },
  };
  function ownsExamId(u, examId, d) { const e = d.exams.find(x => x.id === examId); return e && e.owner === u.id; }
}
/* ===================== Supabase адаптер ===================== */
/* Бүх хамгаалалт сервер талд (schema.sql: RLS + SECURITY DEFINER RPC). Энд зөвхөн дуудлага хийнэ. */
function supaAPI() {
  if (!window.supabase) throw new Error('supabase-js ачаалагдсангүй. Интернэт холболтоо шалгана уу');
  const sb = window.supabase.createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_ANON_KEY, { auth: { persistSession: true, autoRefreshToken: true } });
  const MSG = { 'Invalid login credentials': 'Имэйл эсвэл нууц үг буруу байна', 'User already registered': 'Энэ имэйл бүртгэлтэй байна', 'Email not confirmed': 'Имэйлээ баталгаажуулаагүй байна. Ирсэн имэйлээ шалгана уу' };
  const fail = e => { throw new Error(MSG[e.message] || e.message || 'Алдаа гарлаа'); };
  const rpc = async (name, args) => { const { data, error } = await sb.rpc(name, args || {}); if (error) fail(error); return data; };
  const ok = r => { if (r.error) fail(r.error); return r.data; };
  const profile = async () => {
    const { data: { session } } = await sb.auth.getSession(); if (!session) return null;
    const { data, error } = await sb.from('profiles').select('*').eq('id', session.user.id).maybeSingle();
    if (error || !data || !data.active) { await sb.auth.signOut(); return null; }
    return data;
  };
  return {
    mode: 'supabase',
    init: profile,
    async signIn(email, pw) {
      ok(await sb.auth.signInWithPassword({ email: String(email).trim(), password: pw }));
      const p = await profile(); if (!p) throw new Error('Бүртгэл түр хаагдсан байна. Админтай холбогдоно уу');
      rpc('log_login').catch(() => { }); return p;
    },
    async signUp({ email, pw, name, className, wantTeacher }) {
      if (String(pw).length < 8) throw new Error('Нууц үг хамгийн багадаа 8 тэмдэгт байна');
      const data = ok(await sb.auth.signUp({ email: String(email).trim(), password: pw, options: { data: { full_name: String(name).trim(), class_name: String(className || '').trim(), teacher_requested: !!wantTeacher } } }));
      if (!data.session) { const e = new Error('Бүртгэл үүслээ. Имэйлээ баталгаажуулаад нэвтэрнэ үү'); e.confirm = true; throw e; }
      return profile();
    },
    async signOut() { await sb.auth.signOut(); },
    async updateProfile({ full_name, class_name }) {
      const { data: { session } } = await sb.auth.getSession();
      ok(await sb.from('profiles').update({ full_name: String(full_name).trim().slice(0, 120), class_name: String(class_name || '').trim().slice(0, 40) || null }).eq('id', session.user.id));
      return profile();
    },
    tOverview: () => rpc('teacher_overview'),
    tStudents: () => rpc('teacher_students'),
    classNames: () => rpc('class_names'),
    async listQuestions() {
      const rows = ok(await sb.from('questions').select('*, question_keys(correct)').order('created_at', { ascending: false }));
      return rows.map(q => ({ ...q, correct: (q.question_keys && q.question_keys.correct) || [] }));
    },
    saveQuestion: p => rpc('save_question', { p }),
    async deleteQuestion(id) {
      const { error } = await sb.from('questions').delete().eq('id', id);
      if (error) throw new Error(/foreign key|violates/i.test(error.message) ? 'Асуулт шалгалтад ашиглагдаж байна. Эхлээд шалгалтаас хасна уу' : error.message);
    },
    async listExams() {
      const rows = ok(await sb.from('exams').select('*, exam_questions(question_id, position)').order('created_at', { ascending: false }));
      const codes = ok(await sb.from('exam_codes').select('*'));
      const att = ok(await sb.from('attempts').select('exam_id'));
      return rows.map(e => ({ ...e, qids: (e.exam_questions || []).sort((a, b) => a.position - b.position).map(x => x.question_id), attempts: att.filter(a => a.exam_id === e.id).length, codes: codes.filter(c => c.exam_id === e.id).sort((a, b) => b.expires_at.localeCompare(a.expires_at)) }));
    },
    saveExam: (p, qids) => rpc('save_exam', { p, p_qids: qids }),
    async setReveal(id, v) { ok(await sb.from('exams').update({ show_answers: !!v }).eq('id', id)); },
    setExamStatus: (id, st) => rpc('set_exam_status', { p_exam: id, p_status: st }),
    deleteExam: id => rpc('delete_exam', { p_exam: id }),
    makeCode: (id, minutes) => rpc('make_exam_code', { p_exam: id, p_minutes: Number(minutes) }),
    examResults: id => rpc('teacher_results', { p_exam: id }),
    leaderboard: cls => rpc('leaderboard', { p_class: cls || null }),
    studentEnv: () => rpc('student_env'),
    joinCode: code => rpc('join_exam', { p_code: code }),
    startAttempt: id => rpc('start_attempt', { p_exam: id }),
    saveAnswer: (a, t, q, v) => rpc('save_answer', { p_attempt: a, p_token: t, p_qid: q, p_value: v }),
    submit: (a, t) => rpc('submit_attempt', { p_attempt: a, p_token: t }),
    logEvent: (a, ev) => rpc('log_event', { p_attempt: a, p_event: ev }),
    review: a => rpc('student_review', { p_attempt: a }),
    adminUsers: () => rpc('admin_users'),
    adminSetRole: (id, role) => rpc('admin_set_role', { p_user: id, p_role: role }),
    adminSetActive: (id, v) => rpc('admin_set_active', { p_user: id, p_active: !!v }),
    adminStats: () => rpc('admin_stats'),
    adminExams: () => rpc('admin_exams'),
    adminAudit: () => rpc('admin_audit', { p_limit: 200 }),
  };
}
/* ===================== UI: router, shell, landing, auth ===================== */
let API = null, ME = null, NAVID = 0;
const PAGES = { t: {}, s: {}, a: {} };
const nav = p => { location.hash = '#' + p; };
const homeFor = u => (u.role === 'admin' ? '/a/stats' : u.role === 'teacher' ? '/t/overview' : '/s/home');

const NAVS = {
  t: [['overview', 'Хяналтын самбар', 'home'], ['exams', 'Шалгалтууд', 'file'], ['create', 'Шалгалт үүсгэх', 'plus'], ['bank', 'Асуултын сан', 'db'], ['students', 'Сурагчид', 'users'], ['leaderboard', 'Ангийн чансаа', 'trophy'], ['history', 'Шалгалтын түүх', 'clock'], ['export', 'Үр дүн экспорт', 'download']],
  s: [['home', 'Нүүр', 'home'], ['exams', 'Шалгалтууд', 'file'], ['history', 'Түүх', 'clock'], ['leaderboard', 'Ангийн чансаа', 'trophy'], ['profile', 'Профайл', 'user']],
  a: [['stats', 'Системийн статистик', 'chart'], ['users', 'Хэрэглэгчид ба эрх', 'users'], ['exams', 'Шалгалтын удирдлага', 'file'], ['audit', 'Үйлдлийн бүртгэл', 'log']],
};

function shellHtml(role, key) {
  const links = NAVS[role].map(([k, label, icon]) => `<a href="#/${role}/${k}" class="${k === key ? 'on' : ''}">${ic(icon)}<span>${label}</span></a>`).join('');
  const extra = ME.role === 'admin' && role === 't' ? `<div class="sec">Админ</div><a href="#/a/stats">${ic('shield')}<span>Админ самбар</span></a>` : ME.role === 'admin' && role === 'a' ? `<div class="sec">Багшийн хэсэг</div><a href="#/t/overview">${ic('file')}<span>Багшийн самбар</span></a>` : '';
  const title = { t: 'Багш', s: 'Сурагч', a: 'Админ' }[role];
  return `<div class="shell">
    <aside class="side" id="side" aria-label="Үндсэн цэс">
      <div class="row between">${logo(`#${homeFor(ME)}`)}<button class="btn ghost icon-btn side-x" data-act="menu" aria-label="Цэс хаах">${ic('x')}</button></div>
      <nav class="nav"><div class="sec">${title}</div>${links}${extra}</nav>
      <div class="me"><div class="av">${esc(initials(ME.full_name))}</div><div class="grow"><div style="font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(ME.full_name || ME.email)}</div><div class="faint" style="font-size:12px">${ROLE_LABELS[ME.role]}${ME.class_name ? ' · ' + esc(ME.class_name) : ''}</div></div><button class="btn ghost icon-btn" data-act="logout" aria-label="Гарах" title="Гарах">${ic('logout')}</button></div>
    </aside>
    <div class="scrim" id="scrim" data-act="menu"></div>
    <div class="main">
      <header class="topbar"><button class="btn icon-btn" data-act="menu" aria-label="Цэс нээх">${ic('menu')}</button>${logo(`#${homeFor(ME)}`)}<span style="width:40px"></span></header>
      <main class="page" id="content">${spinner()}</main>
    </div></div>`;
}
ACT.menu = () => { $('#side').classList.toggle('open'); $('#scrim').classList.toggle('open'); };
ACT.logout = async () => { await API.signOut(); ME = null; toast('Системээс гарлаа'); nav('/'); };
const pageHead = (title, sub, actions = '') => `<div class="page-h"><div><h2>${title}</h2>${sub ? `<p>${sub}</p>` : ''}</div>${actions ? `<div class="row">${actions}</div>` : ''}</div>`;

/* ---------- router ---------- */
let shellKey = '';
async function route() {
  cleanupRun();
  const id = ++NAVID;
  const parts = location.hash.replace(/^#\/?/, '').split('/').filter(Boolean);
  const [a, b, c] = parts;
  try {
    if (!a) return landing();
    if (a === 'login') { AUTH_TAB = 'in'; return authView(b || 'student'); }
    if (!ME) return nav('/login/' + ({ t: 'teacher', a: 'admin' }[a] || 'student'));
    const ok = (a === 't' && (ME.role === 'teacher' || ME.role === 'admin')) || (a === 's' && ME.role === 'student') || (a === 'a' && ME.role === 'admin');
    if (!ok) return nav(homeFor(ME));
    if (a === 's' && b === 'exam') return runExam(c);
    const key = PAGES[a][b] ? b : Object.keys(PAGES[a])[0];
    if (!PAGES[a][b]) return nav(`/${a}/${key}`);
    const sk = a + key;
    if (!$('#content') || shellKey !== a) { $('#app').innerHTML = shellHtml(a, key); shellKey = a; }
    else { $$('.nav a').forEach(x => x.classList.toggle('on', x.getAttribute('href') === `#/${a}/${key}`)); $('#content').innerHTML = spinner(); $('#side').classList.remove('open'); $('#scrim').classList.remove('open'); }
    window.scrollTo(0, 0);
    const r = await PAGES[a][b](c);
    if (id !== NAVID) return;
    $('#content').innerHTML = `<div class="rise">${pageHead(r.title, r.sub, r.actions)}${r.body}</div>`;
    if (r.after) r.after();
  } catch (e) {
    if (id !== NAVID) return;
    console.error(e);
    const html = `<div class="card">${empty('alert', 'Алдаа гарлаа', e.message || 'Дахин оролдоно уу', '<button class="btn primary" data-act="reload">Дахин ачаалах</button>')}</div>`;
    if ($('#content')) $('#content').innerHTML = html; else $('#app').innerHTML = `<div class="authwrap">${html}</div>`;
  }
}
ACT.reload = () => route();
window.addEventListener('hashchange', route);
document.addEventListener('change', e => { const el = e.target.closest('[data-change]'); if (el && ACT[el.dataset.change]) Promise.resolve(ACT[el.dataset.change](el, e)).catch(err => toast(err.message, 'bad')); });
document.addEventListener('input', e => { const el = e.target.closest('[data-input]'); if (el && ACT[el.dataset.input]) ACT[el.dataset.input](el, e); });

/* ---------- landing ---------- */
const FEATURES = [
  ['cpu', 'Автомат оноо тооцоолол', 'Илгээсэн даруйд оноо серверт тооцогдоно. Багшийн гар аргаар шалгах хэрэггүй.'],
  ['list', '4 төрлийн асуулт', 'Сонгох, нөхөх, олон сонголттой, зурагтай асуултыг нэг шалгалтад хослуулна.'],
  ['shuffle', 'Санамсаргүй дараалал', 'Асуулт болон хариултын дарааллыг сурагч бүрт өөр өөр холино.'],
  ['timer', 'Цаг тоологч ба автомат илгээлт', 'Хугацаа сервер дээр хяналттай. Дуусахад хариултыг автоматаар илгээнэ.'],
  ['save', 'Автомат хадгалалт', 'Хариулт бүр сервер рүү шууд хадгалагдана. Сүлжээ тасарвал дахин оролдоно.'],
  ['key', 'Хугацаатай шалгалтын код', 'Багш код үүсгэнэ, код тогтоосон хугацаанд л хүчинтэй.'],
  ['shield', 'Role-based хамгаалалт', 'Сурагч, багш, админ тусдаа эрхтэй. Эрхийг зөвхөн админ олгоно.'],
  ['lock', 'Зөв хариулт сурагчид хүрэхгүй', 'Зөв хариулт тусдаа хүснэгтэд, RLS-ээр хаагдсан. API-аар авах боломжгүй.'],
  ['log', 'Үйлдлийн бүртгэл', 'Шалгалтаас гарсан, давхар нэвтэрсэн, код үүсгэсэн бүх үйлдэл бүртгэгдэнэ.'],
];
function landing() {
  shellKey = '';
  const go = ME ? `<a class="btn primary" href="#${homeFor(ME)}">Самбар руу очих ${ic('next')}</a>` : `<a class="btn" href="#/login/student">Сурагч нэвтрэх</a><a class="btn primary" href="#/login/teacher">Багш нэвтрэх</a>`;
  $('#app').innerHTML = `<div class="land">
    <header class="l-nav">${logo()}<div class="row">${API.mode === 'local' ? '<span class="badge warn" title="Supabase холбоогүй">Туршилтын горим</span>' : ''}${go}</div></header>
    <section class="hero">
      <div class="rise">
        <span class="badge blue">${ic('shield', 14)} Онлайн шалгалтын платформ</span>
        <h1 style="margin-top:16px">Шалгалтаа <em>найдвартай, хурдан</em> зохион байгуул</h1>
        <p class="lead">SHALGALT нь багшид шалгалт үүсгэх, асуултын сан бүрдүүлэх, оноог автоматаар тооцоолох боломж олгоно. Сурагч код оруулаад шууд шалгалтаа өгнө.</p>
        <div class="row"><a class="btn primary lg" href="#/login/teacher">${ic('user', 20)} Багш нэвтрэх</a><a class="btn lg" href="#/login/student">${ic('users', 20)} Сурагч нэвтрэх</a></div>
      </div>
      <div class="card sample rise" aria-label="Шалгалтын жишээ харагдац">
        <div class="row between"><span class="badge blue">Жишээ асуулт</span><div class="ring"><svg width="64" height="64" viewBox="0 0 64 64"><circle class="t" cx="32" cy="32" r="28" fill="none" stroke-width="5"/><circle class="p" cx="32" cy="32" r="28" fill="none" stroke-width="5"/></svg><b>${ic('timer', 20)}</b></div></div>
        <h3 style="margin-top:14px;font-size:18px">Монгол Улсын нийслэл аль нь вэ?</h3>
        <div class="opt"><span class="k">А</span>Дархан</div><div class="opt sel"><span class="k">Б</span>Улаанбаатар</div><div class="opt"><span class="k">В</span>Эрдэнэт</div>
        <div class="row between" style="margin-top:16px"><span class="savestate ok">${ic('check', 14)} Хадгалагдлаа</span><span class="faint" style="font-size:12px">Асуулт 1 / 20</span></div>
      </div>
    </section>
    <section class="sect"><h2>Системийн боломжууд</h2><p class="mute" style="margin-bottom:20px">Багш, сурагч, админд хэрэгтэй бүх зүйл нэг дор.</p>
      <div class="grid g3">${FEATURES.map(([i, t, d]) => `<div class="card feat"><div class="chip">${ic(i, 22)}</div><h3>${t}</h3><p>${d}</p></div>`).join('')}</div></section>
    <section class="sect"><h2>Хэрхэн ажилладаг вэ</h2><p class="mute" style="margin-bottom:20px">Гурван алхам.</p>
      <div class="steps"><div class="card"><h3>Багш шалгалт үүсгэнэ</h3><p class="mute">Асуултын сангаас асуулт сонгож, хугацаа болон тохиргоогоо хийнэ.</p></div><div class="card"><h3>Хугацаатай код өгнө</h3><p class="mute">Нийтэлсний дараа код үүсгэж сурагчдад хуваалцана.</p></div><div class="card"><h3>Сурагч өгч, оноо шууд гарна</h3><p class="mute">Автомат хадгалалттай шалгалт, илгээмэгц оноо бодогдоно.</p></div></div></section>
    <footer class="foot"><span>© SHALGALT</span><span><a href="#/login/admin" style="color:inherit">Админ нэвтрэх</a></span></footer></div>`;
}

/* ---------- auth ---------- */
let AUTH_TAB = 'in';
const AUTH_TEXT = { teacher: ['Багш нэвтрэх', 'user'], student: ['Сурагч нэвтрэх', 'users'], admin: ['Админ нэвтрэх', 'shield'] };
function authView(role) {
  if (!AUTH_TEXT[role]) role = 'student';
  shellKey = '';
  if (ME && (role === 'admin' ? ME.role === 'admin' : role === 'teacher' ? ME.role !== 'student' : ME.role === 'student')) return nav(homeFor(ME));
  const canSign = role !== 'admin', up = canSign && AUTH_TAB === 'up';
  $('#app').innerHTML = `<div class="authwrap"><div class="card authcard rise">
    <div style="margin-bottom:18px">${logo()}</div>
    <h2 style="font-size:24px;margin-bottom:4px">${AUTH_TEXT[role][0]}</h2>
    <p class="mute" style="margin-bottom:18px">${up ? (role === 'teacher' ? 'Багшийн бүртгэл админы баталгаажуулалтаар идэвхжинэ.' : 'Шинэ сурагчийн бүртгэл үүсгэх.') : 'Имэйл болон нууц үгээрээ нэвтэрнэ үү.'}</p>
    ${canSign ? `<div class="tabs" role="tablist"><button class="${up ? '' : 'on'}" data-act="authTab" data-tab="in" role="tab">Нэвтрэх</button><button class="${up ? 'on' : ''}" data-act="authTab" data-tab="up" role="tab">Бүртгүүлэх</button></div>` : ''}
    <form data-form="auth" data-role="${role}" class="stack">
      ${up ? `<label class="f">Овог нэр<input class="in" name="name" required maxlength="120" autocomplete="name"></label>` : ''}
      ${up && role === 'student' ? `<label class="f">Анги (жишээ: 10А)<input class="in" name="cls" maxlength="40"></label>` : ''}
      <label class="f">Имэйл<input class="in" type="email" name="email" required autocomplete="email" inputmode="email"></label>
      <label class="f">Нууц үг${up ? ' (8+ тэмдэгт)' : ''}<input class="in" type="password" name="pw" required minlength="${up ? 8 : 1}" autocomplete="${up ? 'new-password' : 'current-password'}"></label>
      <div id="auth-msg"></div>
      <button class="btn primary lg" type="submit">${up ? 'Бүртгүүлэх' : 'Нэвтрэх'}</button>
    </form>
    ${API.mode === 'local' ? `<div class="notice info" style="margin-top:16px">${ic('alert')}<div><b>Туршилтын горим.</b> Өгөгдөл зөвхөн энэ хөтөч дээр хадгалагдана. Админ: <b>admin@shalgalt.mn</b> / <b>Admin12345</b>. Багшийн бүртгэлийг админ батална.</div></div>` : ''}
    <div class="row between" style="margin-top:16px"><a href="#/" class="mute">${ic('back', 16)} Нүүр хуудас</a>${role !== 'admin' ? `<a href="#/login/${role === 'teacher' ? 'student' : 'teacher'}" class="mute">${role === 'teacher' ? 'Сурагч нэвтрэх' : 'Багш нэвтрэх'}</a>` : ''}</div>
  </div></div>`;
}
ACT.authTab = el => { AUTH_TAB = el.dataset.tab; authView(location.hash.split('/')[2] || 'student'); };
ACT.auth = async f => {
  const role = f.dataset.role, fd = new FormData(f), msg = $('#auth-msg'), up = role !== 'admin' && AUTH_TAB === 'up';
  const show = (t, k = 'bad') => { msg.innerHTML = `<div class="notice ${k}">${ic('alert')}<span>${esc(t)}</span></div>`; };
  msg.innerHTML = '';
  let u;
  try {
    u = up ? await API.signUp({ email: fd.get('email'), pw: fd.get('pw'), name: fd.get('name'), className: fd.get('cls'), wantTeacher: role === 'teacher' }) : await API.signIn(fd.get('email'), fd.get('pw'));
  } catch (e) { return show(e.message, e.confirm ? 'info' : 'bad'); }
  if (role === 'teacher' && u.role === 'student') {
    await API.signOut();
    AUTH_TAB = 'in';
    return show(u.teacher_requested ? 'Багшийн эрхийн хүсэлт илгээгдсэн. Админ баталсны дараа нэвтэрнэ үү.' : 'Энэ бүртгэл сурагчийн эрхтэй. "Сурагч нэвтрэх" хэсгийг ашиглана уу.', 'info');
  }
  if (role === 'student' && u.role !== 'student') { await API.signOut(); return show('Энэ бүртгэл сурагчийн биш. "Багш нэвтрэх" хэсгийг ашиглана уу.'); }
  if (role === 'admin' && u.role !== 'admin') { await API.signOut(); return show('Админы эрх байхгүй байна.'); }
  ME = u; toast('Тавтай морил, ' + (u.full_name || u.email), 'good'); nav(homeFor(u));
};

/* ---------- boot ---------- */
async function boot() {
  try {
    API = CONFIG.SUPABASE_URL && CONFIG.SUPABASE_ANON_KEY ? supaAPI() : localAPI();
    ME = await API.init();
  } catch (e) { $('#app').innerHTML = `<div class="authwrap"><div class="card authcard">${empty('alert', 'Эхлүүлж чадсангүй', e.message)}</div></div>`; return; }
  route();
}
/* ===================== UI: багш ===================== */
const TYPE_LABELS = { single: 'Сонгох', multi: 'Олон сонголттой', fill: 'Нөхөх', image: 'Зурагтай' };
const nl = s => esc(s).replace(/\n/g, '<br>');

PAGES.t.overview = async () => {
  const o = await API.tOverview();
  const per = (o.per_exam || []).filter(x => x.avg_pct != null).map(x => ({ label: x.title, value: Number(x.avg_pct) }));
  const dist = (o.dist || Array(10).fill(0)), dmax = Math.max(4, ...dist);
  const total = dist.reduce((a, b) => a + b, 0);
  return {
    title: 'Хяналтын самбар', sub: 'Таны шалгалтуудын бодит үзүүлэлт',
    actions: `<a class="btn primary" href="#/t/create">${ic('plus')} Шалгалт үүсгэх</a>`,
    body: `<div class="grid g4">${statCard('users', o.students, 'Нийт сурагч')}${statCard('file', o.exams, 'Нийт шалгалт')}${statCard('check', o.attempted, 'Шалгалт өгсөн сурагч')}${statCard('chart', o.avg == null ? '—' : o.avg + '%', 'Дундаж оноо')}</div>
    <div class="grid g2" style="margin-top:16px">
      <div class="card"><div class="card-h"><h3>${ic('chart')} Шалгалт бүрийн дундаж оноо</h3></div>${per.length ? barChart(per) : empty('chart', 'Өгөгдөл алга', 'Сурагч шалгалт өгсний дараа график энд гарна.')}</div>
      <div class="card"><div class="card-h"><h3>${ic('chart')} Онооны тархалт</h3><span class="faint">${total} оролдлого</span></div>${total ? barChart(dist.map((c, i) => ({ label: `${i * 10}–${(i + 1) * 10}`, value: c })), { max: dmax, suffix: '' }) : empty('chart', 'Өгөгдөл алга', 'Илгээсэн шалгалт байхгүй байна.')}</div>
    </div>
    <div class="card" style="margin-top:16px"><div class="card-h"><h3>Хурдан үйлдэл</h3></div><div class="row"><a class="btn" href="#/t/bank">${ic('db')} Асуулт нэмэх</a><a class="btn" href="#/t/exams">${ic('file')} Шалгалтууд</a><a class="btn" href="#/t/leaderboard">${ic('trophy')} Ангийн чансаа</a><a class="btn" href="#/t/export">${ic('download')} Үр дүн экспортлох</a></div></div>`,
  };
};

/* ---------- шалгалтууд ---------- */
const examBadges = e => { const [l, k] = STATUS_LABELS[e.status]; return `<span class="badge ${k}">${l}</span>${e.class_name ? `<span class="badge blue">${esc(e.class_name)}</span>` : ''}<span class="badge">${ic('timer', 13)} ${e.duration_min} мин</span><span class="badge">${e.qids.length} асуулт</span><span class="badge">${e.attempts} оролдлого</span>`; };
PAGES.t.exams = async () => {
  const list = await API.listExams();
  const now = Date.now();
  const card = e => {
    const codes = e.codes.filter(c => new Date(c.expires_at) > now).slice(0, 3);
    return `<div class="card stack" data-exam="${e.id}">
      <div class="row between"><div class="grow"><h3 style="font-size:18px">${esc(e.title)}</h3>${e.description ? `<p class="mute" style="margin-top:2px">${esc(e.description)}</p>` : ''}</div></div>
      <div class="row">${examBadges(e)}</div>
      ${codes.length ? `<div class="row">${codes.map(c => `<span class="badge good num" title="Хүчинтэй хугацаа">${ic('key', 13)} <b>${c.code}</b> · ${fmtDate(c.expires_at)} хүртэл</span>`).join('')}</div>` : ''}
      <label class="chk"><input type="checkbox" data-change="reveal" data-id="${e.id}" ${e.show_answers ? 'checked' : ''}> Дууссаны дараа сурагчид зөв хариултыг харуулах</label>
      <div class="row">
        ${e.status === 'draft' ? `<button class="btn primary sm" data-act="setStatus" data-id="${e.id}" data-st="published">${ic('play', 14)} Нийтлэх</button><a class="btn sm" href="#/t/create/${e.id}">${ic('edit', 14)} Засах</a>` : ''}
        ${e.status === 'published' ? `<button class="btn primary sm" data-act="codeModal" data-id="${e.id}">${ic('key', 14)} Код үүсгэх</button><button class="btn sm" data-act="results" data-id="${e.id}">${ic('chart', 14)} Үр дүн</button><button class="btn sm" data-act="setStatus" data-id="${e.id}" data-st="closed">${ic('lock', 14)} Хаах</button>` : ''}
        ${e.status === 'closed' ? `<button class="btn sm" data-act="results" data-id="${e.id}">${ic('chart', 14)} Үр дүн</button><button class="btn sm" data-act="setStatus" data-id="${e.id}" data-st="published">Дахин нээх</button>` : ''}
        <button class="btn danger sm" data-act="delExam" data-id="${e.id}" data-title="${esc(e.title)}">${ic('trash', 14)} Устгах</button>
      </div></div>`;
  };
  return {
    title: 'Шалгалтууд', sub: 'Нийтлэх, код үүсгэх, үр дүн харах', actions: `<a class="btn primary" href="#/t/create">${ic('plus')} Шалгалт үүсгэх</a>`,
    body: list.length ? `<div class="grid g2">${list.map(card).join('')}</div>` : `<div class="card">${empty('file', 'Шалгалт алга', 'Асуултын сангаас асуулт сонгож эхний шалгалтаа үүсгээрэй.', `<a class="btn primary" href="#/t/create">${ic('plus')} Шалгалт үүсгэх</a>`)}</div>`,
  };
};
ACT.reveal = async el => { await API.setReveal(el.dataset.id, el.checked); toast(el.checked ? 'Хариулт харуулахыг зөвшөөрлөө' : 'Хариулт харуулахыг хаалаа', 'good'); };
ACT.setStatus = async el => { await API.setExamStatus(el.dataset.id, el.dataset.st); toast(el.dataset.st === 'published' ? 'Шалгалт нийтлэгдлээ' : 'Шалгалт хаагдлаа', 'good'); route(); };
ACT.delExam = el => confirmModal('Шалгалт устгах', `"${el.dataset.title}" шалгалт болон бүх үр дүн устана. Үргэлжлүүлэх үү?`, 'Устгах', async () => { await API.deleteExam(el.dataset.id); toast('Устгалаа', 'good'); route(); });
ACT.codeModal = el => {
  openModal(`${modalHead('Шалгалтын код үүсгэх')}<form data-form="codeMake" data-id="${el.dataset.id}" class="stack"><label class="f">Кодын хүчинтэй хугацаа<select class="in" name="m"><option value="15">15 минут</option><option value="30">30 минут</option><option value="60" selected>1 цаг</option><option value="180">3 цаг</option><option value="1440">1 өдөр</option><option value="10080">7 хоног</option></select></label><p class="mute" style="font-size:13px">Хугацаа дууссаны дараа код ашиглах боломжгүй болно. Кодоор орсон сурагч шалгалтаа өөрийн цагаар өгнө.</p><button class="btn primary" type="submit">${ic('key')} Код үүсгэх</button></form>`, 'sm');
};
ACT.codeMake = async f => {
  const r = await API.makeCode(f.dataset.id, new FormData(f).get('m'));
  window.__code = r.code;
  $('.modal').innerHTML = `${modalHead('Шалгалтын код')}<div class="codebox num" id="codeval">${r.code}</div><p class="mute" style="text-align:center;margin-top:10px">${fmtDate(r.expires_at)} хүртэл хүчинтэй</p><div class="row" style="justify-content:center;margin-top:16px"><button class="btn primary" data-act="copyCode">${ic('copy')} Хуулах</button><button class="btn" data-act="closeModal">Болсон</button></div>`;
  route();
};
ACT.copyCode = async () => { try { await navigator.clipboard.writeText(window.__code); toast('Код хууллаа', 'good'); } catch (e) { const r = document.createRange(); r.selectNodeContents($('#codeval')); const s = getSelection(); s.removeAllRanges(); s.addRange(r); toast('Кодыг сонгосон, Ctrl+C дарна уу'); } };

const csvRows = (rs, title) => rs.map(r => { const sub = !!r.submitted_at; return [...(title ? [title] : []), r.full_name, r.class_name || '', r.email || '', sub ? r.score : '', sub ? r.max_score : '', sub ? pct(r.score, r.max_score) : '', sub ? 'Дууссан' : 'Үргэлжилж байна', r.leave_count, fmtDate(r.started_at), fmtDate(r.submitted_at)]; });
const CSV_H = ['Нэр', 'Анги', 'Имэйл', 'Оноо', 'Нийт оноо', 'Хувь', 'Төлөв', 'Шалгалтаас гарсан', 'Эхэлсэн', 'Илгээсэн'];
const safeName = s => String(s).replace(/[^\p{L}\p{N}_-]+/gu, '_').slice(0, 40);
ACT.results = async el => {
  const id = el.dataset.id; const exams = await API.listExams(); const e = exams.find(x => x.id === id); const rs = await API.examResults(id);
  const done = rs.filter(r => r.submitted_at), ps = done.map(r => pct(r.score, r.max_score));
  const avg = ps.length ? Math.round(ps.reduce((a, b) => a + b, 0) / ps.length * 10) / 10 : null;
  openModal(`${modalHead('Үр дүн · ' + esc(e ? e.title : ''))}
    <div class="grid g4" style="grid-template-columns:repeat(auto-fit,minmax(120px,1fr));margin-bottom:16px"><div><div class="faint">Оролцогч</div><b class="num" style="font-size:20px">${rs.length}</b></div><div><div class="faint">Дундаж</div><b class="num" style="font-size:20px">${avg == null ? '—' : avg + '%'}</b></div><div><div class="faint">Дээд</div><b class="num" style="font-size:20px">${ps.length ? Math.max(...ps) + '%' : '—'}</b></div><div><div class="faint">Доод</div><b class="num" style="font-size:20px">${ps.length ? Math.min(...ps) + '%' : '—'}</b></div></div>
    ${rs.length ? `<div class="tw card pad0"><table><thead><tr><th>Сурагч</th><th>Анги</th><th class="r">Оноо</th><th class="r">Хувь</th><th>Төлөв</th><th>Гарсан</th></tr></thead><tbody>${rs.map(r => `<tr><td>${esc(r.full_name)}</td><td>${esc(r.class_name || '—')}</td><td class="r num">${r.submitted_at ? `${r.score}/${r.max_score}` : '—'}</td><td class="r">${r.submitted_at ? scoreBadge(pct(r.score, r.max_score)) : '—'}</td><td>${r.submitted_at ? '<span class="badge good">Дууссан</span>' : '<span class="badge warn">Өгч байна</span>'}</td><td>${r.leave_count ? `<span class="badge warn" title="Шалгалтын хуудаснаас гарсан тоо">${r.leave_count}×</span>` : '<span class="faint">—</span>'}</td></tr>`).join('')}</tbody></table></div>` : empty('users', 'Оролцогч алга', 'Энэ шалгалтыг хэн ч өгөөгүй байна.')}
    ${rs.length ? `<div class="row" style="margin-top:14px;justify-content:flex-end"><button class="btn primary" data-act="exportOne" data-id="${id}" data-title="${esc(e ? e.title : 'shalgalt')}">${ic('download')} CSV экспорт</button></div>` : ''}`);
};
ACT.exportOne = async el => { const rs = await API.examResults(el.dataset.id); showCSV(`shalgalt_${safeName(el.dataset.title)}.csv`, CSV_H, csvRows(rs)); };

/* ---------- шалгалт үүсгэх ---------- */
PAGES.t.create = async id => {
  const [bank, classes, exams] = await Promise.all([API.listQuestions(), API.classNames(), id ? API.listExams() : Promise.resolve([])]);
  const ex = id ? exams.find(x => x.id === id) : null;
  if (id && !ex) throw new Error('Шалгалт олдсонгүй');
  const sel = new Set(ex ? ex.qids : []);
  const v = ex || { title: '', description: '', class_name: '', duration_min: 45, shuffle_q: true, shuffle_a: true, show_answers: false };
  const locked = ex && ex.attempts > 0;
  return {
    title: ex ? 'Шалгалт засах' : 'Шалгалт үүсгэх', sub: 'Үндсэн мэдээлэл, асуултууд, тохиргоо',
    body: !bank.length ? `<div class="card">${empty('db', 'Асуултын сан хоосон', 'Шалгалтад оруулах асуулт эхлээд хэрэгтэй.', `<a class="btn primary" href="#/t/bank">${ic('plus')} Асуулт нэмэх</a>`)}</div>` : `
    <form data-form="saveExam" data-id="${ex ? ex.id : ''}" class="stack">
      ${locked ? `<div class="notice">${ic('alert')}<span>Сурагч өгч эхэлсэн тул энэ шалгалтыг засах боломжгүй.</span></div>` : ''}
      <div class="card"><div class="card-h"><h3>Үндсэн мэдээлэл</h3></div><div class="formgrid">
        <label class="f" style="grid-column:1/-1">Шалгалтын нэр<input class="in" name="title" required maxlength="150" value="${esc(v.title)}"></label>
        <label class="f" style="grid-column:1/-1">Тайлбар (заавал биш)<textarea class="in" name="description" maxlength="500">${esc(v.description || '')}</textarea></label>
        <label class="f">Анги (энэ ангийн сурагчид шууд харна)<input class="in" name="class_name" list="cls" maxlength="40" value="${esc(v.class_name || '')}" placeholder="Хоосон бол зөвхөн кодоор"><datalist id="cls">${classes.map(c => `<option value="${esc(c)}">`).join('')}</datalist></label>
        <label class="f">Үргэлжлэх хугацаа (минут)<input class="in" type="number" name="duration_min" min="1" max="300" required value="${v.duration_min}"></label></div>
        <div class="stack" style="margin-top:16px;gap:10px"><label class="chk"><input type="checkbox" name="shuffle_q" ${v.shuffle_q ? 'checked' : ''}> Асуултын дарааллыг санамсаргүй холих</label><label class="chk"><input type="checkbox" name="shuffle_a" ${v.shuffle_a ? 'checked' : ''}> Хариултын дарааллыг санамсаргүй холих</label><label class="chk"><input type="checkbox" name="show_answers" ${v.show_answers ? 'checked' : ''}> Дууссаны дараа сурагчид зөв хариултыг харуулах</label></div></div>
      <div class="card pad0"><div style="padding:20px 20px 12px"><div class="card-h" style="margin:0"><h3>Асуулт сонгох</h3><div class="row"><span class="badge blue num" id="selinfo">0 асуулт · 0 оноо</span></div></div><input class="in" id="qsearch" data-input="pickFilter" placeholder="Асуултаас хайх…" style="margin-top:12px"></div>
        <div class="scroll" id="picklist">${bank.map(q => `<label class="pick" data-text="${esc((q.text + ' ' + (q.tag || '')).toLowerCase())}"><input type="checkbox" name="q" value="${q.id}" data-pts="${q.points}" data-change="pickSum" ${sel.has(q.id) ? 'checked' : ''}><span class="grow" style="min-width:0;word-break:break-word">${esc(q.text.length > 140 ? q.text.slice(0, 140) + '…' : q.text)}</span><span class="badge">${TYPE_LABELS[q.type]}</span>${q.tag ? `<span class="badge blue">${esc(q.tag)}</span>` : ''}<span class="badge num">${q.points} оноо</span></label>`).join('')}</div></div>
      <div class="row" style="justify-content:flex-end"><a class="btn" href="#/t/exams">Болих</a><button class="btn" type="submit" name="mode" value="draft" ${locked ? 'disabled' : ''}>${ic('save')} Ноорог хадгалах</button><button class="btn primary" type="submit" name="mode" value="publish" ${locked ? 'disabled' : ''}>${ic('play')} Хадгалаад нийтлэх</button></div>
    </form>`,
    after: () => ACT.pickSum(),
  };
};
ACT.pickSum = () => { const c = $$('#picklist input:checked'); const el = $('#selinfo'); if (el) el.textContent = `${c.length} асуулт · ${c.reduce((s, x) => s + Number(x.dataset.pts), 0)} оноо`; };
ACT.pickFilter = el => { const t = el.value.trim().toLowerCase(); $$('#picklist .pick').forEach(r => { r.style.display = !t || r.dataset.text.includes(t) ? '' : 'none'; }); };
ACT.saveExam = async (f, ev) => {
  const fd = new FormData(f), qids = fd.getAll('q'), publish = ev.submitter && ev.submitter.value === 'publish';
  if (!qids.length) throw new Error('Дор хаяж 1 асуулт сонгоно уу');
  const p = { id: f.dataset.id || null, title: fd.get('title'), description: fd.get('description'), class_name: fd.get('class_name'), duration_min: Number(fd.get('duration_min')), shuffle_q: fd.has('shuffle_q'), shuffle_a: fd.has('shuffle_a'), show_answers: fd.has('show_answers') };
  const id = await API.saveExam(p, qids);
  if (publish) await API.setExamStatus(id, 'published');
  toast(publish ? 'Шалгалт нийтлэгдлээ' : 'Ноорог хадгалагдлаа', 'good'); nav('/t/exams');
};

/* ---------- асуултын сан ---------- */
let BANK = [], BF = { q: '', type: '' }, QF = null;
PAGES.t.bank = async () => {
  BANK = await API.listQuestions(); BF = { q: '', type: '' };
  return {
    title: 'Асуултын сан', sub: 'Бүх асуултаа нэг дор удирдана', actions: `<button class="btn primary" data-act="qNew">${ic('plus')} Асуулт нэмэх</button>`,
    body: `<div class="card pad0"><div class="row" style="padding:16px 16px 0"><input class="in grow" data-input="bankFilter" data-k="q" placeholder="Хайх (асуулт, сэдэв)…" style="min-width:200px"><select class="in" data-change="bankFilter" data-k="type" style="width:auto"><option value="">Бүх төрөл</option>${Object.entries(TYPE_LABELS).map(([k, l]) => `<option value="${k}">${l}</option>`).join('')}</select></div><div id="banklist" style="margin-top:8px"></div></div>`,
    after: renderBank,
  };
};
ACT.bankFilter = el => { BF[el.dataset.k] = el.value; renderBank(); };
function renderBank() {
  const t = BF.q.trim().toLowerCase(), l = BANK.filter(q => (!BF.type || q.type === BF.type) && (!t || (q.text + ' ' + (q.tag || '')).toLowerCase().includes(t)));
  $('#banklist').innerHTML = !BANK.length ? empty('db', 'Асуулт алга', 'Эхний асуултаа нэмээрэй.', `<button class="btn primary" data-act="qNew">${ic('plus')} Асуулт нэмэх</button>`) : !l.length ? empty('db', 'Олдсонгүй', 'Хайлтад тохирох асуулт алга.') :
    l.map(q => `<div class="qrow"><div class="qt"><div class="row" style="margin-bottom:6px"><span class="badge blue">${TYPE_LABELS[q.type]}</span>${q.tag ? `<span class="badge">${esc(q.tag)}</span>` : ''}<span class="badge num">${q.points} оноо</span>${q.image ? `<span class="badge">${ic('image', 13)} зурагтай</span>` : ''}</div><div>${nl(q.text.length > 220 ? q.text.slice(0, 220) + '…' : q.text)}</div>
      <div class="faint" style="margin-top:6px;font-size:13px">${q.type === 'fill' ? 'Зөв: ' + q.correct.map(esc).join(' / ') : q.options.map((o, i) => `<span class="${q.correct.includes(i) ? 'good' : ''}">${q.correct.includes(i) ? '✓ ' : ''}${esc(o)}</span>`).join(' · ')}</div></div>
      <div class="row" style="flex-wrap:nowrap"><button class="btn sm icon-btn" data-act="qEdit" data-id="${q.id}" aria-label="Засах" title="Засах">${ic('edit', 16)}</button><button class="btn sm icon-btn danger" data-act="qDel" data-id="${q.id}" aria-label="Устгах" title="Устгах">${ic('trash', 16)}</button></div></div>`).join('');
}
ACT.qNew = () => { QF = { id: null, type: 'single', text: '', image: null, options: ['', '', '', ''], correct: [], accepted: '', points: 1, tag: '' }; qfRender(); };
ACT.qEdit = el => { const q = BANK.find(x => x.id === el.dataset.id); QF = { ...q, options: [...q.options], correct: [...q.correct], accepted: q.type === 'fill' ? q.correct.join('\n') : '', tag: q.tag || '' }; qfRender(); };
ACT.qDel = el => confirmModal('Асуулт устгах', 'Энэ асуултыг сангаас устгах уу?', 'Устгах', async () => { await API.deleteQuestion(el.dataset.id); toast('Устгалаа', 'good'); BANK = BANK.filter(q => q.id !== el.dataset.id); renderBank(); });
function qfRender() {
  const q = QF, choice = q.type !== 'fill', multi = q.type === 'multi';
  openModal(`${modalHead(q.id ? 'Асуулт засах' : 'Асуулт нэмэх')}<form data-form="qSave" class="stack">
    <div class="formgrid"><label class="f">Асуултын төрөл<select class="in" data-qf="type" data-change="qfType">${Object.entries(TYPE_LABELS).map(([k, l]) => `<option value="${k}" ${q.type === k ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
      <label class="f">Оноо<input class="in" type="number" min="1" max="100" data-qf="points" data-input="qfIn" value="${q.points}"></label>
      <label class="f">Сэдэв (заавал биш)<input class="in" data-qf="tag" data-input="qfIn" maxlength="60" value="${esc(q.tag)}"></label></div>
    <label class="f">Асуулт<textarea class="in" data-qf="text" data-input="qfIn" required maxlength="2000">${esc(q.text)}</textarea></label>
    <div class="stack" style="gap:8px"><div class="f" style="font-size:13px;color:var(--mute)">Зураг ${q.type === 'image' ? '(заавал)' : '(заавал биш)'}</div>${q.image ? `<img class="thumb" src="${q.image}" alt="Асуултын зураг"><div><button class="btn sm danger" type="button" data-act="qfImgDel">${ic('trash', 14)} Зураг хасах</button></div>` : ''}<input class="in" type="file" accept="image/png,image/jpeg,image/webp" data-change="qfImg"></div>
    ${choice ? `<div class="stack" style="gap:8px"><div class="f" style="font-size:13px;color:var(--mute)">Сонголтууд · зөв хариултыг тэмдэглэнэ ${multi ? '(олон сонгож болно)' : ''}</div>${q.options.map((o, i) => `<div class="optrow"><input type="${multi ? 'checkbox' : 'radio'}" name="qcor" ${q.correct.includes(i) ? 'checked' : ''} data-change="qfCor" data-i="${i}" aria-label="Зөв хариулт ${i + 1}"><input class="in" data-qf-opt="${i}" data-input="qfOpt" data-i="${i}" maxlength="300" placeholder="Сонголт ${i + 1}" value="${esc(o)}"><button type="button" class="btn ghost icon-btn" data-act="qfOptDel" data-i="${i}" aria-label="Хасах" ${q.options.length <= 2 ? 'disabled' : ''}>${ic('x', 16)}</button></div>`).join('')}${q.options.length < 8 ? `<div><button type="button" class="btn sm" data-act="qfOptAdd">${ic('plus', 14)} Сонголт нэмэх</button></div>` : ''}</div>` :
      `<label class="f">Зөв хариултууд (мөр бүрт нэг, томоор/жижгээр ялгахгүй)<textarea class="in" data-qf="accepted" data-input="qfIn" placeholder="Улаанбаатар&#10;УБ">${esc(q.accepted)}</textarea></label>`}
    <div class="row" style="justify-content:flex-end"><button type="button" class="btn" data-act="closeModal">Болих</button><button class="btn primary" type="submit">${ic('save')} Хадгалах</button></div></form>`);
}
ACT.qfIn = el => { const k = el.dataset.qf; QF[k] = k === 'points' ? Number(el.value) : el.value; };
ACT.qfOpt = el => { QF.options[Number(el.dataset.i)] = el.value; };
ACT.qfCor = el => { const i = Number(el.dataset.i); if (QF.type === 'multi') { QF.correct = el.checked ? [...new Set([...QF.correct, i])] : QF.correct.filter(x => x !== i); } else QF.correct = [i]; };
ACT.qfType = el => { QF.type = el.value; if (QF.type !== 'multi' && QF.correct.length > 1) QF.correct = [QF.correct[0]]; qfRender(); };
ACT.qfOptAdd = () => { QF.options.push(''); qfRender(); };
ACT.qfOptDel = el => { const i = Number(el.dataset.i); QF.options.splice(i, 1); QF.correct = QF.correct.filter(x => x !== i).map(x => (x > i ? x - 1 : x)); qfRender(); };
ACT.qfImgDel = () => { QF.image = null; qfRender(); };
ACT.qfImg = async el => { const f = el.files[0]; if (!f) return; QF.image = await fileToDataUrl(f); qfRender(); };
ACT.qSave = async () => {
  const q = QF; let options = [], correct = [];
  if (q.type === 'fill') correct = q.accepted.split('\n').map(s => s.trim()).filter(Boolean);
  else { const map = {}; q.options.forEach((o, i) => { if (o.trim()) { map[i] = options.length; options.push(o.trim()); } }); correct = q.correct.filter(i => i in map).map(i => map[i]); }
  if (q.type !== 'fill' && options.length < 2) throw new Error('Дор хаяж 2 сонголт бөглөнө үү');
  if (!correct.length) throw new Error('Зөв хариултаа сонгоно уу');
  await API.saveQuestion({ id: q.id, type: q.type, text: q.text, image: q.image, options, correct, points: q.points || 1, tag: q.tag });
  closeModal(); toast('Асуулт хадгалагдлаа', 'good'); route();
};

/* ---------- сурагчид ---------- */
let STU = [], SF = { q: '', c: '' };
PAGES.t.students = async () => {
  STU = await API.tStudents(); SF = { q: '', c: '' }; const cls = [...new Set(STU.map(s => s.class_name).filter(Boolean))].sort();
  return {
    title: 'Сурагчдын жагсаалт', sub: `${STU.length} идэвхтэй сурагч`,
    body: `<div class="card pad0"><div class="row" style="padding:16px"><input class="in grow" data-input="stuFilter" data-k="q" placeholder="Нэр, имэйлээр хайх…" style="min-width:200px"><select class="in" data-change="stuFilter" data-k="c" style="width:auto"><option value="">Бүх анги</option>${cls.map(c => `<option>${esc(c)}</option>`).join('')}</select></div><div class="tw"><table><thead><tr><th>Сурагч</th><th>Анги</th><th class="r">Өгсөн шалгалт</th><th class="r">Дундаж</th></tr></thead><tbody id="stubody"></tbody></table></div></div>`,
    after: renderStu,
  };
};
ACT.stuFilter = el => { SF[el.dataset.k] = el.value; renderStu(); };
function renderStu() {
  const t = SF.q.trim().toLowerCase(), l = STU.filter(s => (!SF.c || s.class_name === SF.c) && (!t || (s.full_name + ' ' + s.email).toLowerCase().includes(t)));
  $('#stubody').innerHTML = l.length ? l.map(s => `<tr><td><div class="row" style="flex-wrap:nowrap"><div class="av">${esc(initials(s.full_name))}</div><div><div style="font-weight:600">${esc(s.full_name)}</div><div class="faint" style="font-size:12px">${esc(s.email)}</div></div></div></td><td>${s.class_name ? `<span class="badge blue">${esc(s.class_name)}</span>` : '—'}</td><td class="r num">${s.exams}</td><td class="r">${s.avg == null ? '<span class="faint">—</span>' : scoreBadge(Number(s.avg))}</td></tr>`).join('') : `<tr><td colspan="4">${empty('users', STU.length ? 'Олдсонгүй' : 'Сурагч алга', STU.length ? 'Хайлтад тохирох сурагч алга.' : 'Сурагчид бүртгүүлсний дараа энд харагдана.')}</td></tr>`;
}

/* ---------- чансаа ---------- */
const lbTable = (rows, meId) => rows.length ? `<div class="tw"><table><thead><tr><th style="width:60px">#</th><th>Сурагч</th><th>Анги</th><th class="r">Шалгалт</th><th class="r">Дундаж</th></tr></thead><tbody>${rows.map((r, i) => `<tr class="${i < 3 ? 'lb-' + (i + 1) : ''}" ${r.student_id === meId ? 'style="outline:1px solid var(--blue-2);outline# SHALGALT — суулгах заавар

Файлууд:
- `schema.sql` — Supabase-ийн бүх хүснэгт, Row Level Security, серверийн функцүүд
- `index.html` — бүтэн апп (нэг файл)

## 1. Supabase тохируулах (10 минут)
1. supabase.com дээр шинэ project үүсгэнэ.
2. **SQL Editor** руу `schema.sql`-ийн бүх агуулгыг буулгаж **Run** дарна.
3. **Authentication → Providers → Email**: хурдан туршихын тулд "Confirm email"-ийг унтрааж болно (бодит ашиглалтад асаалттай үлдээнэ).
4. **Project Settings → API** хэсгээс `Project URL` болон `anon public` түлхүүрийг хуулна.
5. `index.html` дотор `const CONFIG = { SUPABASE_URL: "", SUPABASE_ANON_KEY: "" }` хэсэгт утгуудаа бичнэ. `anon` түлхүүр нийтэд ил байх зориулалттай. `service_role` түлхүүрийг ХЭЗЭЭ Ч энд бүү бич.
6. `index.html`-ийг дурын статик хостод (Netlify, Vercel, GitHub Pages, Supabase Storage) байрлуулна.

## 2. Эхний админ
1. Аппаар сурагчаар бүртгүүлнэ.
2. SQL Editor дээр: `update public.profiles set role = 'admin' where email = 'ТАНЫ@ИМЭЙЛ';`
3. "Админ нэвтрэх" хуудсаар нэвтэрч, багшийн хүсэлтүүдийг "Хэрэглэгчид ба эрх" хэсгээс батална.

## Хамгаалалтын загвар
- Шинэ хэрэглэгч эхэндээ ҮРГЭЛЖ `student`. Бүртгэлийн metadata-аар эрх өгөх боломжгүй. Багш/админ эрхийг зөвхөн админ олгоно.
- Зөв хариулт `question_keys` хүснэгтэд, сурагчид policy байхгүй. Шалгалтын асуултыг `start_attempt()` буцаахдаа зөв хариултгүй дамжуулна.
- Оноог `submit_attempt()` серверт тооцно. Хугацаа дууссан оролдлогыг сервер өөрөө автоматаар илгээнэ.
- Шалгалтын код нь хугацаатай (`exam_codes.expires_at`), 6 тэмдэгт.
- Давхар нэвтрэлт: нэг шалгалтад нэг идэвхтэй токен. Шинэ цонх нээгдэхэд хуучин нь хүчингүй болж, үйлдэл `audit_logs`-д бүртгэгдэнэ.
- Шалгалтаас гарсан (tab солих) үйлдэл `attempts.leave_count` ба `audit_logs`-д бүртгэгдэнэ.
- Хүснэгтийн бичих эрхийг сурагчаас хассан. Бүх бичих үйлдэл SECURITY DEFINER функцээр дамжина.

## Мэдэж байх зүйл
- Хөтөч дээрх "tab солих" бүртгэл нь таамаглал өгөх хэрэгсэл. Тэвчихгүй хүн хөтөч хөгжүүлэгчийн хэрэгслээр тойрч чадна. Серверийн хугацаа, токен, оноо тооцоо нь тойрч болдоггүй.
- Хугацаа дууссан боловч хэн ч дахин нэвтрээгүй оролдлогыг сервер дараагийн хандалтад (чансаа, үр дүн, өгөгдөл унших) автоматаар илгээнэ. Яг цагтаа илгээхийг хүсвэл Supabase дээр `pg_cron` идэвхжүүлж `select public._finalize_overdue();`-ийг минут бүр ажиллуулна (superuser-ээр).
- Зураг асуултад `data:` URL хэлбэрээр (720px, JPEG) хадгалагдана. Олон зурагтай бол Supabase Storage руу шилжүүлэх нь дээр.
ganzorig# glowing-palm-tree