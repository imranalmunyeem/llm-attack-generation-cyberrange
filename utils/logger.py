import logging
import os

LOG_FOLDER = "experiments/logs"

os.makedirs(LOG_FOLDER, exist_ok=True)

logging.basicConfig(
    filename=f"{LOG_FOLDER}/generation.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def log_message(message):
    logging.info(message)