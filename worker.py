from app import create_app
from app.services.collection_worker import ScheduledCollectionWorker


def main():
    app = create_app()
    worker = ScheduledCollectionWorker(app)
    try:
        worker.run_forever()
    except KeyboardInterrupt:
        app.logger.info("scheduled collection worker stopping")
        worker.stop()


if __name__ == "__main__":
    main()
