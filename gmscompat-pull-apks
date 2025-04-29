#!/bin/bash

set -o errexit -o nounset -o pipefail

APPS=(com.android.vending com.google.android.gms com.google.android.gsf)

rm -rf extracted-apps-old
[[ -d extracted-apps ]] && mv extracted-apps extracted-apps-old
mkdir extracted-apps
cd extracted-apps

for app in ${APPS[@]}; do
    mkdir $app
    paths=$(adb shell pm path $app)
    for package in $paths; do
        adb pull ${package#package:} $app/
    done
done
