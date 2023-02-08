#!/usr/bin/env python3

import datetime
import hashlib
import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path

channels = "stable", "beta", "alpha"

apps = {}

for channel in channels:
    top = "apps-" + channel
    for src in sorted(os.listdir(top)):
        metadata = {"label": "", "versionCode": -1, "dependencies": [], "packages": [], "hashes": []}

        src_dir = os.path.join(top, src)
        src_packages = os.listdir(src_dir)
        if len(src_packages) == 1:
            base_apk = src_packages[0]
        else:
            base_apk = "base.apk"

        badging = subprocess.check_output(["aapt2", "dump", "badging", os.path.join(src_dir, base_apk)])
        lines = badging.split(b"\n")

        for kv in shlex.split(lines[0].decode()):
            if kv.startswith("versionCode"):
                version_code = int(kv.split("=")[1])
                metadata["versionCode"] = version_code
            elif kv.startswith("name"):
                app_id = kv.split("=")[1]

        for line in lines[1:-1]:
            kv = shlex.split(line.decode())
            if kv[0].startswith("application-label:"):
                metadata["label"] = kv[0].split(":")[1]
            elif kv[0].startswith("uses-static-library:"):
                metadata["dependencies"].append(kv[1].split("=")[1])
            elif kv[0].startswith("sdkVersion"):
                metadata["minSdkVersion"] = int(kv[0].split(":")[1])

        if src in ("com.android.vending.33", "com.google.android.gms.33"):
            metadata["minSdkVersion"] = 33

        if app_id == "com.google.android.gms":
            metadata["dependencies"] = ["com.google.android.gsf"]
        elif app_id == "com.android.vending":
            metadata["dependencies"] = ["com.google.android.gsf", "com.google.android.gms"]

        if app_id == "app.grapheneos.pdfviewer":
            metadata["originalPackage"] = "org.grapheneos.pdfviewer"

        app_dir = os.path.join("apps", "packages", app_id, str(version_code))
        assert os.path.isdir(app_dir)

        for package in sorted(os.listdir(app_dir)):
            if not package.endswith(".apk"):
                continue

            h = hashlib.new("sha256")
            with open(os.path.join(app_dir, package), "rb") as f:
                h.update(f.read())
            metadata["hashes"].append(h.hexdigest())
            metadata["packages"].append(package)

        apps.setdefault(app_id, {}).setdefault(channel, []).append(metadata)

metadata = {
    "time": int(datetime.datetime.utcnow().timestamp()),
    "apps": apps
}

with open("apps/metadata.0.json", "w") as f:
    json.dump(metadata, f, separators=(',', ':'))

subprocess.check_output(["signify", "-S", "-s", "apps.0.sec", "-m", "apps/metadata.0.json", "-x", "apps/metadata.0.json.0.sig"])
