#!/usr/bin/env python3

import datetime
import hashlib
import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path

top = "extracted-apps"

shutil.rmtree("apps", ignore_errors=True)
os.mkdir("apps")
shutil.copy("apps.0.pub", "apps")

apps = {}

for app_id in os.listdir(top):
    metadata = {"packages": [], "hashes": []}
    apps[app_id] = {"stable": metadata}

    src_dir = os.path.join(top, app_id)
    src_packages = os.listdir(src_dir)
    if len(src_packages) == 1:
        base_apk = src_packages[0]
    else:
        base_apk = "base.apk"

    badging = subprocess.check_output(["aapt2", "dump", "badging", os.path.join(src_dir, base_apk)])
    line = badging.split(b"\n")[0]
    for kv in shlex.split(line.decode()):
        if kv.startswith("versionCode"):
            version_code = int(kv.split("=")[1])
            metadata["versionCode"] = version_code

    app_dir = os.path.join("apps", "packages", app_id, str(version_code))
    if len(src_packages) == 1:
        os.makedirs(app_dir)
        shutil.copyfile(os.path.join(src_dir, base_apk), os.path.join(app_dir, "base.apk"))
    else:
        shutil.copytree(src_dir, app_dir)

    for package in os.listdir(app_dir):
        h = hashlib.new("sha256")
        with open(os.path.join(app_dir, package), "rb") as f:
            h.update(f.read())
        metadata["hashes"].append(h.hexdigest())
        metadata["packages"].append(package)

metadata = {
    "time": int(datetime.datetime.utcnow().timestamp()),
    "apps": apps
}

with open("apps/metadata.json", "w") as f:
    json.dump(metadata, f, separators=(',', ':'))

subprocess.check_output(["signify", "-S", "-s", "apps.0.sec", "-m", "apps/metadata.json", "-x", "apps/metadata.json.0.sig"])
