#!/bin/sh

fuzz_list_cmd="cargo fuzz list"

$fuzz_list_cmd | while read -r target; do
  echo "----- fuzzing $target ------"
  RUST_BACKTRACE=1 cargo fuzz run "$target" -- -max_total_time="${1:-1200}"
done
