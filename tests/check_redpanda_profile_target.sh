#!/bin/sh
set -eu

project_file=${1:?usage: check_redpanda_profile_target.sh DelProfils1.dev [makefile.win]}
makefile=${2:-}
if ! rg -Fq 'FileName = src/ProfileTarget.cpp' "$project_file" &&
   ! rg -Fq 'FileName = src\ProfileTarget.cpp' "$project_file"; then
    echo "FAIL: RedPanda project does not compile/link src/ProfileTarget.cpp"
    exit 1
fi
if ! rg -Fq 'FileName = src/ProfileTarget.h' "$project_file" &&
   ! rg -Fq 'FileName = src\ProfileTarget.h' "$project_file"; then
    echo "FAIL: RedPanda project does not list src/ProfileTarget.h"
    exit 1
fi
if [ -n "$makefile" ]; then
    if ! rg -Fq 'src/ProfileTarget.o' "$makefile" ||
       ! rg -Fq '"src/ProfileTarget.o"' "$makefile"; then
        echo "FAIL: makefile.win does not compile and link src/ProfileTarget.o"
        exit 1
    fi
fi
echo "RedPandaProjectLinkTests: PASS"
