#!/usr/bin/env python3

import os
import re
import shlex
import shutil
import subprocess
import sys

for i in range(1, len(sys.argv)):
    path = sys.argv[i]
    print("\nimporting " + path)

    badging = subprocess.check_output(["aapt2", "dump", "badging", path])
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

    if not os.path.isdir(dest_dir):
        os.makedirs(dest_dir)
        with open(dest_dir + "/props.toml", "w") as f:
            f.write("channel = \"alpha\"\n")

    if is_split:
        shutil.copy(path, dest_dir)
        print("copied to " + dest_dir)
    else:
        dest_path = dest_dir + "/base.apk"
        shutil.copyfile(path, dest_path)
        print("copied to " + dest_path)

    v4_sig_path = path + ".idsig"
    if os.path.isfile(v4_sig_path):
        if is_split:
            shutil.copy(v4_sig_path, dest_dir)
        else:
            shutil.copyfile(v4_sig_path, dest_dir + "/base.apk.idsig")

