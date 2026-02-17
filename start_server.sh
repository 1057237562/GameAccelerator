#!/bin/bash
echo "Starting Game Accelerator Server..."
cd "$(dirname "$0")"
python3 -m server.main "$@"
