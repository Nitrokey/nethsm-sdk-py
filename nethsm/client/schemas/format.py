import datetime
import decimal
import functools
import uuid


@functools.lru_cache()
def as_date(arg: str) -> datetime.date:
    """
    type = "string"
    format = "date"
    """
    return datetime.date.fromisoformat(arg)

@functools.lru_cache()
def as_datetime(arg: str) -> datetime.datetime:
    """
    type = "string"
    format = "date-time"
    """
    # datetime.fromisoformat() only accepts a trailing "Z" on Python 3.11+.
    if arg.endswith(("Z", "z")):
        arg = arg[:-1] + "+00:00"
    return datetime.datetime.fromisoformat(arg)

@functools.lru_cache()
def as_decimal(arg: str) -> decimal.Decimal:
    """
    Applicable when storing decimals that are sent over the wire as strings
    type = "string"
    format = "number"
    """
    return decimal.Decimal(arg)

@functools.lru_cache()
def as_uuid(arg: str) -> uuid.UUID:
    """
    type = "string"
    format = "uuid"
    """
    return uuid.UUID(arg)
