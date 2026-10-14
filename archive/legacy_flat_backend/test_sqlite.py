import asyncio
import aiosqlite
import os

async def test():
    db_path = "vigil_new.db"
    print(f"Checking if {db_path} exists: {os.path.exists(db_path)}")
    if os.path.exists(db_path):
        print(f"Deleting {db_path} and associated files")
        os.remove(db_path)
        if os.path.exists(db_path + "-shm"):
            os.remove(db_path + "-shm")
        if os.path.exists(db_path + "-wal"):
            os.remove(db_path + "-wal")
    print("Connecting to SQLite...")
    conn = await aiosqlite.connect(db_path, timeout=30.0)
    print("Connected!")
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute("PRAGMA busy_timeout=30000")
    await conn.commit()
    print("PRAGMAs set!")
    await conn.close()
    print("Done!")

asyncio.run(test())
