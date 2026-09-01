from app.core.redis import redis


async def check_rate_limit(
    key: str,
    limit: int,
    window: int,
) -> tuple[bool, int]:
    count = await redis.incr(key)

    if count == 1:
        await redis.expire(key, window)

    if count > limit:
        retry_after = await redis.ttl(key)
        return False, max(retry_after, 0)

    return True, 0