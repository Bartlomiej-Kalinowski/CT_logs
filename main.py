from logs_collector import LogCollector
from config import Config as Cf
import certstream


def on_open():
    print(f"Connected to {Cf.CERT_LOGS_URL}", flush=True)


def on_error(error):
    print(f"Certstream error: {error}", flush=True)


def main():
    print(f"Starting listener on {Cf.CERT_LOGS_URL}", flush=True)
    data_source = LogCollector(Cf)
    certstream.listen_for_events(
        data_source.process_message,
        Cf.CERT_LOGS_URL,
        on_open=on_open,
        on_error=on_error,
    )

if __name__ == "__main__":
    main()
