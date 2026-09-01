from redis.exceptions import RedisError
from app.core.redis import redis_client

ACCOUNT_LOGIN_FAILURE_LIMIT = 5
ACCOUNT_LOGIN_FAILURE_WINDOW = 15 * 60


async def check_account_login_failure(email: str) -> int:
    """
    Track failed login attempts for a specific account.

    Returns the current number of failed attempts.
    """

    key = f"login_failure:account:{email.lower()}"

    try:
        attempts = await redis_client.incr(key)

        if attempts == 1:
            await redis_client.expire(
                key,
                ACCOUNT_LOGIN_FAILURE_WINDOW,
            )

        return attempts

    except RedisError:
        return 0


async def is_account_login_blocked(email: str) -> bool:
    """
    Check whether the account has exceeded
    the failed-login limit.
    """

    key = f"login_failure:account:{email.lower()}"

    try:
        attempts = await redis_client.get(key)

        if attempts is None:
            return False

        return int(attempts) >= ACCOUNT_LOGIN_FAILURE_LIMIT

    except RedisError:
        return False



async def reset_account_login_failures(email: str) -> None:
    """
    Reset failed login attempts after successful login.
    """

    key = f"login_failure:account:{email.lower()}"

    try:
        await redis_client.delete(key)

    except RedisError:
        pass


async def get_account_login_retry_after(email: str) -> int:
    """
    Return the number of seconds until the account
    login-failure lockout expires.
    """

    key = f"login_failure:account:{email.lower()}"

    try:
        ttl = await redis_client.ttl(key)

        if ttl < 0:
            return ACCOUNT_LOGIN_FAILURE_WINDOW

        return ttl

    except RedisError:
        return ACCOUNT_LOGIN_FAILURE_WINDOW