import json

from .errors import ConfigError


DEFAULT_CONFIG = {"min_string_length": 5, "entropy_threshold": 7.2}


def load_config(path=None):
    config = DEFAULT_CONFIG.copy()

    if not path:
        return config

    try:
        with open(path, "r", encoding="utf-8") as f:
            value = json.load(f)
    except FileNotFoundError as e:
        raise ConfigError(f"Config file not found: {path}") from e
    except json.JSONDecodeError as e:
        raise ConfigError(f"Invalid JSON config: {e.msg}") from e
    except OSError as e:
        raise ConfigError(f"Cannot read config file: {e}") from e

    if not isinstance(value, dict):
        raise ConfigError("Config must contain a JSON object.")

    if "min_string_length" in value:
        n = value["min_string_length"]
        if not isinstance(n, int) or n < 1:
            raise ConfigError("min_string_length must be a positive integer.")
        config["min_string_length"] = n

    if "entropy_threshold" in value:
        n = value["entropy_threshold"]
        if not isinstance(n, (int, float)) or not 0 <= n <= 8:
            raise ConfigError("entropy_threshold must be between 0 and 8.")
        config["entropy_threshold"] = float(n)

    return config
