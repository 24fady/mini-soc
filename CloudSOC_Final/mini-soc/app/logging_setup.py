"""Structured JSON logging. One JSON object per line, ready for CloudWatch Logs."""
import json
import logging
import os
import sys
from datetime import datetime, timezone

LOGGER_NAME = "minisoc"


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
        }
        data = getattr(record, "event_data", None)
        if data:
            payload.update(data)
        else:
            payload["message"] = record.getMessage()
        return json.dumps(payload, default=str)


def setup_logging(log_file=""):
    logger = logging.getLogger(LOGGER_NAME)
    if logger.handlers:
        return
    logger.setLevel(logging.INFO)
    logger.propagate = False
    formatter = JsonFormatter()

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    if log_file:
        try:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except OSError as exc:
            logger.warning("File logging disabled: %s", exc)


def log_event(event, level=logging.INFO, **fields):
    logging.getLogger(LOGGER_NAME).log(
        level, event, extra={"event_data": {"event": event, **fields}}
    )
