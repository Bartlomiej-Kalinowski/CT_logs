import ssl

from logs_collector import LogCollector
from config import Config as Cf
import certstream


def on_open():
    print(f"Connected to {Cf.CERT_LOGS_URL}", flush=True)


def on_error(*args):
    print(f"Certstream error: {args}", flush=True)




def main():
    print(f"Starting listener on {Cf.CERT_LOGS_URL}", flush=True)

    data_source = LogCollector(Cf)
    print(f"Logs will be saved to {Cf.LOG_FILE_PATH}", flush=True)

    certstream.listen_for_events(
        message_callback=data_source.process_message,
        url=Cf.CERT_LOGS_URL,
        skip_heartbeats=False,
        on_open=on_open,
        on_error=on_error,
    )


if __name__ == "__main__":
    main()
