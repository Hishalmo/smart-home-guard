"""Supabase client helpers for the SmartHomeGuard API."""

from __future__ import annotations

import os

from supabase import Client, create_client

def make_user_client(jwt: str) -> Client:
    """Return a Supabase client that forwards the caller's JWT.

    This lets row-level security enforce per-user scoping without the
    backend needing to stamp user_id manually on every insert.
    """
    supabase_url = os.getenv("SUPABASE_URL", "")
    publishable_key = os.getenv("SUPABASE_PUBLISHABLE_KEY", "")

    if not supabase_url or not publishable_key:
        raise RuntimeError(
            "SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY must be configured"
        )

    client = create_client(supabase_url, publishable_key)
    client.postgrest.auth(jwt)
    return client
