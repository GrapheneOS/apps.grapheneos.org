#!/usr/bin/env python3

import os
import re
import shlex
import shutil
import subprocess
import sys

from os import path

for i in range(1, len(sys.argv)):
    src = sys.argv[i]
    print("\nimporting " + src)

    badging = subprocess.check_output(["aapt2", "dump", "badging", src])
    lines = badging.split(b"\n")

    version = None
    pkg_name = None
    abi = None
    is_split = False

    for kv in shlex.split(lines[0].decode()):
        if kv.startswith("versionCode"):
            version = kv.split("=")[1]
        elif kv.startswith("name"):
            pkg_name = kv.split("=")[1]
        elif kv.startswith("split"):
            is_split = True

    assert version != None
    assert pkg_name != None

    dest_dir = "apps/packages/" + pkg_name + "/" + version

    if not path.isdir(dest_dir):
        os.makedirs(dest_dir)
        with open(dest_dir + "/channel.toml", "w") as f:
            f.write("channel = \"alpha\"\n")

    dest_path = path.join(dest_dir, path.basename(src) if is_split else "base.apk")
    if path.exists(dest_path):
        raise Exception(dest_path + " already exists. Make sure to delete its caches and deltas before replacing it.")
    shutil.copyfile(src, dest_path)
    print("copied to " + dest_path)

    v4_sig_path = src + ".idsig"
    if path.isfile(v4_sig_path):
        if is_split:
            shutil.copy(v4_sig_path, dest_dir)
        else:
            shutil.copyfile(v4_sig_path, dest_dir + "/base.apk.idsig")

    if not is_split:
        props_path = src + ".props.toml"
        if path.isfile(props_path):
            dest_props_path = dest_dir + "/props.toml"
            shutil.copyfile(props_path, dest_props_path)
            print("copied " + props_path + " to " + dest_props_path)
