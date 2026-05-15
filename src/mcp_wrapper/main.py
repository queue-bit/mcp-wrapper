from __future__ import annotations

import argparse
import logging
import sys

import uvicorn

from .config import load_config
from .server import build_app


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP Security Wrapper")
    parser.add_argument("--config", default="config", help="Path to config directory")
    parser.add_argument("--log-level", default=None, help="Override log level (DEBUG/INFO/WARNING)")
    args = parser.parse_args()

    config = load_config(args.config)
    level = args.log_level or config.logging.level
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )

    app = build_app(config, args.config)
    uvicorn.run(app, host=config.server.host, port=config.server.port)


if __name__ == "__main__":
    main()
