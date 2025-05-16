#!/bin/sh

fuzz_list_cmd="cargo fuzz list"

$fuzz_list_cmd | while read -r target; do
  echo "----- fuzzing $target ------"
  target_cmd="cargo fuzz run $target -- -timeout=300"
  $target_cmd
done
