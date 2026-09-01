from app.core.redis import redis_client,redis


LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60

FORGOT_PASSWORD_MAX_ATTEMPTS = 5
FORGOT_PASSWORD_WINDOW_SECONDS = 15 * 60

RESET_PASSWORD_LIMIT = 10
RESET_PASSWORD_WINDOW = 900



def _login_key(ip_address: str, email: str) -> str:
    normalized_email = email.strip().lower()

    return f"auth:login:failed:{ip_address}:{normalized_email}"


async def is_login_blocked(
    ip_address: str,
    email: str,
) -> bool:
    key = _login_key(ip_address, email)

    attempts = await redis_client.get(key)

    if attempts is None:
        return False

    return int(attempts) >= LOGIN_MAX_ATTEMPTS


async def record_failed_login(
    ip_address: str,
    email: str,
) -> int:
    key = _login_key(ip_address, email)

    attempts = await redis_client.incr(key)

    # Set expiration only when the counter is first created.
    if attempts == 1:
        await redis_client.expire(
            key,
            LOGIN_WINDOW_SECONDS,
        )

    return attempts


async def clear_failed_logins(
    ip_address: str,
    email: str,
) -> None:
    key = _login_key(ip_address, email)

    await redis_client.delete(key)


async def get_login_retry_after(
    ip_address: str,
    email: str,
) -> int:
    key = _login_key(ip_address, email)

    ttl = await redis_client.ttl(key)

    if ttl <= 0:
        return LOGIN_WINDOW_SECONDS

    return ttl

def _forgot_password_key(
    ip_address: str,
    email: str,
) -> str:
    normalized_email = email.strip().lower()

    return (
        f"auth:forgot-password:failed:"
        f"{ip_address}:{normalized_email}"
    )

async def is_forgot_password_blocked(
    ip_address: str,
    email: str,
) -> bool:
    key = _forgot_password_key(
        ip_address,
        email,
    )

    attempts = await redis_client.get(key)

    if attempts is None:
        return False

    return int(attempts) >= FORGOT_PASSWORD_MAX_ATTEMPTS


async def record_forgot_password_attempt(
    ip_address: str,
    email: str,
) -> int:
    key = _forgot_password_key(
        ip_address,
        email,
    )

    attempts = await redis_client.incr(key)

    if attempts == 1:
        await redis_client.expire(
            key,
            FORGOT_PASSWORD_WINDOW_SECONDS,
        )

    return attempts


async def get_forgot_password_retry_after(
    ip_address: str,
    email: str,
) -> int:
    key = _forgot_password_key(
        ip_address,
        email,
    )

    ttl = await redis_client.ttl(key)

    if ttl <= 0:
        return FORGOT_PASSWORD_WINDOW_SECONDS

    return ttl

async def check_rate_limit(
    key: str,
    limit: int,
    window: int,
) -> bool:
    count = await redis.incr(key)

    if count == 1:
        await redis.expire(key, window)

    return count <= limit