#!/bin/bash

set -o errexit -o nounset -o pipefail

APPS=(com.android.vending com.google.android.gms com.google.android.gsf)
BRANCH="apps-stable"

if [[ $# -eq 1 ]]; then
    if [[ $1 != "stable" && $1 != "beta" ]]; then
        exit 1
    fi
    BRANCH="apps-$1"
fi


rm -rf apps-stable-old
[[ -d apps-stable ]] && mv apps-stable apps-stable-old
if [[ $BRANCH == "apps-beta" ]]; then
    rm -rf apps-stable
    [[ -d apps-beta ]] && mv apps-beta apps-stable
fi

rm -rf $BRANCH
mkdir $BRANCH
cd $BRANCH

for app in ${APPS[@]}; do
    mkdir $app
    for package in $(adb shell pm path $app); do
        adb pull ${package#package:} $app/
    done
done
