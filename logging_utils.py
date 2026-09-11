import logging


def setup_logging(level):
    numeric = getattr(logging, level.upper(), logging.WARNING)
    logging.basicConfig(level=numeric, format="%(levelname)s: %(message)s")
    return logging.getLogger("pescope")
