#!/bin/bash
echo "Starting Game Accelerator Client..."
cd "$(dirname "$0")"
python3 -m client.main "$@"
