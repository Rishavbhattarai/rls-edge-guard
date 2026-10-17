-- Public profiles: anyone can read, only the owner can write.
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  display_name text not null
);
alter table public.profiles enable row level security;

-- rls-edge-guard-ignore RLS010: profiles are public by design
create policy "profiles: public read" on public.profiles for select to anon, authenticated
  using (true);
create policy "profiles: owner insert" on public.profiles for insert to authenticated
  with check ((select auth.uid()) = id);
create policy "profiles: owner update" on public.profiles for update to authenticated
  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);
