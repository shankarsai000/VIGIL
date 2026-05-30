"""Async database helper for both PostgreSQL and SQLite-backed persistence."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Iterable, Optional, Sequence
import aiosqlite
import asyncpg


def _convert_placeholders_postgres(sql: str) -> str:
    """Converts SQLite-style ? placeholders to PostgreSQL $1, $2..."""
    if "?" not in sql:
        return sql

    parts = sql.split("?")
    rebuilt = []
    for idx, part in enumerate(parts[:-1], start=1):
        rebuilt.append(part)
        rebuilt.append(f"${idx}")
    rebuilt.append(parts[-1])
    return "".join(rebuilt)


class PostgresDatabase:
    """Lightweight asyncpg wrapper that accepts SQLite-style placeholders."""

    def __init__(self, dsn: str):
        self.dsn = dsn
        self.pool: Optional[asyncpg.Pool] = None

    async def connect(self) -> None:
        if self.pool is None:
            self.pool = await asyncpg.create_pool(dsn=self.dsn, min_size=1, max_size=10)

    async def close(self) -> None:
        if self.pool is not None:
            await self.pool.close()
            self.pool = None

    @asynccontextmanager
    async def acquire(self):
        if self.pool is None:
            raise RuntimeError("Database pool not initialized")
        async with self.pool.acquire() as conn:
            yield conn

    async def execute(self, sql: str, params: Optional[Sequence] = None) -> None:
        converted = _convert_placeholders_postgres(sql)
        values = [] if params is None else list(params)
        async with self.acquire() as conn:
            await conn.execute(converted, *values)

    async def fetch(self, sql: str, params: Optional[Sequence] = None) -> list[asyncpg.Record]:
        converted = _convert_placeholders_postgres(sql)
        values = [] if params is None else list(params)
        async with self.acquire() as conn:
            return await conn.fetch(converted, *values)

    async def fetchrow(self, sql: str, params: Optional[Sequence] = None) -> Optional[asyncpg.Record]:
        converted = _convert_placeholders_postgres(sql)
        values = [] if params is None else list(params)
        async with self.acquire() as conn:
            return await conn.fetchrow(converted, *values)

    async def execute_many(self, statements: Iterable[str]) -> None:
        async with self.acquire() as conn:
            async with conn.transaction():
                for statement in statements:
                    await conn.execute(statement)


class SQLiteDatabase:
    """Lightweight aiosqlite wrapper for SQLite persistence."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        if self.conn is None:
            self.conn = await aiosqlite.connect(self.db_path)
            self.conn.row_factory = aiosqlite.Row

    async def close(self) -> None:
        if self.conn is not None:
            await self.conn.close()
            self.conn = None

    @asynccontextmanager
    async def acquire(self):
        if self.conn is None:
            raise RuntimeError("Database connection not initialized")
        yield self.conn

    async def execute(self, sql: str, params: Optional[Sequence] = None) -> None:
        async with self.acquire() as conn:
            await conn.execute(sql, params or ())
            await conn.commit()

    async def fetch(self, sql: str, params: Optional[Sequence] = None) -> list[aiosqlite.Row]:
        async with self.acquire() as conn:
            cursor = await conn.execute(sql, params or ())
            return await cursor.fetchall()

    async def fetchrow(self, sql: str, params: Optional[Sequence] = None) -> Optional[aiosqlite.Row]:
        async with self.acquire() as conn:
            cursor = await conn.execute(sql, params or ())
            return await cursor.fetchone()

    async def execute_many(self, statements: Iterable[str]) -> None:
        async with self.acquire() as conn:
            for statement in statements:
                await conn.execute(statement)
            await conn.commit()


def create_database(database_url: str):
    """Factory function to create appropriate database instance based on URL."""
    if database_url.startswith("postgresql://") or database_url.startswith("postgres://"):
        return PostgresDatabase(database_url)
    else:
        # Assume SQLite
        return SQLiteDatabase(database_url)
