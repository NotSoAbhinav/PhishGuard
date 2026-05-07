import logging

logging.basicConfig(
    filename="phishguard.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def log_result(url, result, score):
    logging.info(f"{url} | {result} | Risk: {score}%")