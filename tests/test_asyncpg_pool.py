"""
Tests for asyncpg pool initialization, closure, and SQL translation.

TDD RED phase: These tests define the expected behavior for the asyncpg
connection pool layer in db.py and config constants in config.py.
"""

import os
import sys
import asyncio
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

# Ensure MoltGrid package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestAsyncpgPoolConfig:
    """Test config.py asyncpg pool constants."""

    def test_asyncpg_min_size_default(self):
        """ASYNCPG_MIN_SIZE defaults to 5."""
        from config import ASYNCPG_MIN_SIZE
        assert ASYNCPG_MIN_SIZE == 5

    def test_asyncpg_max_size_default(self):
        """ASYNCPG_MAX_SIZE defaults to 20."""
        from config import ASYNCPG_MAX_SIZE
        assert ASYNCPG_MAX_SIZE == 20

    def test_asyncpg_command_timeout_default(self):
        """ASYNCPG_COMMAND_TIMEOUT defaults to 30."""
        from config import ASYNCPG_COMMAND_TIMEOUT
        assert ASYNCPG_COMMAND_TIMEOUT == 30


class TestTranslateSqlAsyncpg:
    """Test _translate_sql_asyncpg converts ? to $1, $2, etc."""

    def test_basic_placeholder_conversion(self):
        """? placeholders become $1, $2, $3 numbered params."""
        from db import _translate_sql_asyncpg
        sql = "SELECT * FROM t WHERE a=? AND b=?"
        result = _translate_sql_asyncpg(sql)
        assert "$1" in result
        assert "$2" in result
        assert "?" not in result

    def test_three_placeholders(self):
        """Three ? become $1, $2, $3."""
        from db import _translate_sql_asyncpg
        sql = "INSERT INTO t (a, b, c) VALUES (?, ?, ?)"
        result = _translate_sql_asyncpg(sql)
        assert "$1" in result
        assert "$2" in result
        assert "$3" in result
        assert "?" not in result

    def test_no_placeholders_unchanged(self):
        """SQL without ? is returned unchanged (except datetime transforms)."""
        from db import _translate_sql_asyncpg
        sql = "SELECT * FROM t WHERE a=1"
        result = _translate_sql_asyncpg(sql)
        assert result == sql

    def test_datetime_offset_conversion(self):
        """datetime(col, '-300 seconds') converts to CAST/INTERVAL."""
        from db import _translate_sql_asyncpg
        sql = "SELECT * FROM t WHERE created_at > datetime(created_at, '-300 seconds')"
        result = _translate_sql_asyncpg(sql)
        assert "CAST" in result
        assert "INTERVAL" in result
        assert "datetime" not in result.lower() or "datetime" not in result

    def test_datetime_simple_conversion(self):
        """datetime('now') converts to CAST('now' AS TIMESTAMP)."""
        from db import _translate_sql_asyncpg
        sql = "SELECT * FROM t WHERE created_at > datetime('now')"
        result = _translate_sql_asyncpg(sql)
        assert "CAST" in result
        assert "datetime" not in result.lower()

    def test_question_mark_in_string_literal_preserved(self):
        """? inside string literals should not be converted."""
        from db import _translate_sql_asyncpg
        sql = "SELECT * FROM t WHERE name='what?' AND id=?"
        result = _translate_sql_asyncpg(sql)
        # The id param should become $1
        assert "$1" in result


class TestInitAsyncpgPool:
    """Test init_asyncpg_pool and close_asyncpg_pool."""

    def test_pool_none_when_sqlite(self):
        """Pool is None when DB_BACKEND=sqlite (no crash)."""
        import db
        # _asyncpg_pool should be None by default (sqlite mode)
        assert db._asyncpg_pool is None

    @pytest.mark.asyncio
    async def test_init_creates_pool_when_postgres(self):
        """init_asyncpg_pool creates pool when DB_BACKEND=postgres and DATABASE_URL is set."""
        import db
        mock_pool = AsyncMock()
        with patch.object(db, "DB_BACKEND", "postgres"), \
             patch.object(db, "DATABASE_URL", "postgresql://user:pass@localhost/test"), \
             patch("db.asyncpg") as mock_asyncpg:
            mock_asyncpg.create_pool = AsyncMock(return_value=mock_pool)
            await db.init_asyncpg_pool()
            mock_asyncpg.create_pool.assert_called_once()
            assert db._asyncpg_pool is mock_pool
            # Clean up
            db._asyncpg_pool = None

    @pytest.mark.asyncio
    async def test_close_pool_cleanly(self):
        """close_asyncpg_pool cleanly closes pool."""
        import db
        mock_pool = AsyncMock()
        db._asyncpg_pool = mock_pool
        await db.close_asyncpg_pool()
        mock_pool.close.assert_called_once()
        assert db._asyncpg_pool is None
