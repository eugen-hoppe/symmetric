import os

from functools import wraps
from typing import Callable


def get_or_generate_salt(env_var: str | None, salt: str = "", len_salt: int = 8):
    if env_var is not None and salt == "":
        salt = str(os.getenv(env_var, "_"))
    if len(salt) < len_salt:
        salt = os.urandom(16).hex()
    return salt


def try_except(
    errors: tuple[type[Exception], ...] = (Exception,),
    raise_: type[Exception] | None = None,
    txt_: str = "",
    info_: str = " [ PROD: add '#debug'-tag for full traceback chain ]",
) -> Callable:
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: any, **kwargs: any) -> any:
            try:
                return func(*args, **kwargs)
            except errors as err:
                if raise_ is not None:
                    from_error = err if "#debug" in txt_ else None
                    raise raise_(txt_ + info_) from from_error
                raise err

        return wrapper

    return decorator
