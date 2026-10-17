-- Owner-only notes, written the way the rls-policy-author skill describes.
create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  body text not null,
  created_at timestamptz not null default now()
);
alter table public.notes enable row level security;
create index notes_user_id_idx on public.notes (user_id);

create policy "notes: owner select" on public.notes for select to authenticated
  using ((select auth.uid()) = user_id);
create policy "notes: owner insert" on public.notes for insert to authenticated
  with check ((select auth.uid()) = user_id);
create policy "notes: owner update" on public.notes for update to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "notes: owner delete" on public.notes for delete to authenticated
  using ((select auth.uid()) = user_id);
