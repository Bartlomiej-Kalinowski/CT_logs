from config import Config as Cf
# from logs_collector import LogCollector
from test import LogCollector

if __name__ == "__main__":
    print(f"Polling {Cf.POLL_URL} every {Cf.POLL_INTERVAL}s", flush=True)
    print(f"Logs -> {Cf.LOG_FILE_PATH}", flush=True)
    LogCollector(Cf).poll()

