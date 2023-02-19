import logging
from .server import main


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    main()