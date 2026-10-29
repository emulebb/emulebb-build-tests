#!/bin/sh
set -eu

if [ "$#" -lt 4 ] || [ "$1" != "--pid-file" ]; then
    echo "usage: wsl_managed_process.sh --pid-file PATH -- COMMAND [ARG ...]" >&2
    exit 2
fi

pid_file=$2
shift 2
if [ "$1" != "--" ]; then
    echo "managed process command separator is required" >&2
    exit 2
fi
shift
if [ "$#" -eq 0 ]; then
    echo "managed process command is required" >&2
    exit 2
fi

mkdir -p "$(dirname "$pid_file")"
printf '%s\n' "$$" > "$pid_file"
exec "$@"
