#!/usr/bin/env python3

import base64
import collections
import copy
import datetime
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tomli

def load_props(dir, name):
    path = os.path.join(dir, name + ".toml")
    if os.path.isfile(path):
        with open(path, "rb") as f:
            return tomli.load(f)
    else:
        return {}

def load_signature(apk_path):
    apksigner_output = subprocess.check_output(["apksigner", "verify", "--print-certs", "--verbose", apk_path])
    sig_hash = None
    for line in apksigner_output.split(b'\n'):
        split = re.split("^Signer .+ certificate SHA-256 digest: ", line.decode())
        if (len(split) == 2):
            if (sig_hash is not None):
                if ("maxSdkVersion=" in line.decode()):
                    # ignore secondary maxSdk-restricted signers
                    continue
                # Intentionally don't support APKs that have more than one signer
                raise Exception(apk_path + " has more than one signer")
            sig_hash = split[1]

    if sig_hash is None:
        raise Exception("didn't find signature of " + apk_path)

    return sig_hash

all_abis = {"arm64-v8a", "x86_64", "armeabi-v7a", "x86"}
# file name ABI qualifier replaces "-" with "_"
abis_dict = {
    "arm64_v8a": "arm64-v8a",
    "x86_64": "x86_64",
    "armeabi_v7a": "armeabi-v7a",
    "x86": "x86",
}

def remove_old_pkg_variants(orig_dict):
    # Build a dict that maps package versions to props that determine whether this version would be overriden by a newer
    # version (e.g. release channel, list of ABIs, dependencies, minSdk).
    # To make sure new props are not missed. use exclusion, not inclusion filtering

    dict = copy.deepcopy(orig_dict)

    for pkg_props in dict.values():
        for k in ["apkHashes", "apkSizes", "apkGzSizes", "apkBrSizes", "apks",
                  "versionCode", "versionName", "label", "description", "releaseNotes", ]:
            pkg_props.pop(k, None)

    pkg_versions = sorted(orig_dict.keys(), key=int)

    # build a new dict that contains only those package versions that are not overriden by newer ones
    result = collections.OrderedDict()

    for i in range(0, len(pkg_versions)):
        pkg_version = pkg_versions[i]
        props = dict[pkg_version]
        is_old = False
        for j in range(i + 1, len(dict.keys())):
            if dict[pkg_versions[j]] == props:
                # all relevant props are the same, pkg_version is overriden by pkg_versions[j]
                is_old = True
                break

        if not is_old:
            result[pkg_version] = orig_dict[pkg_version]

    return result

assert subprocess.call("./compress-apks") == 0

packages_dir = "apps/packages"
packages = {}

for pkg_name in sorted(os.listdir(packages_dir)):
    pkg_container_path = os.path.join(packages_dir, pkg_name)
    common_props = load_props(pkg_container_path, "common-props")

    if os.path.isfile(os.path.join(pkg_container_path, "icon.webp")):
        common_props["iconType"] = "webp"

    pkg_signatures = common_props["signatures"]
    package_variants = collections.OrderedDict()

    for pkg_version in sorted(os.listdir(pkg_container_path)):
        pkg_path = os.path.join(pkg_container_path, pkg_version)
        if not os.path.isdir(pkg_path):
            continue

        print("processing " + pkg_name + "/" + pkg_version)
        pkg_props = {"versionCode": int(pkg_version), "apks": [], "apkHashes": [],
                     "apkSizes": [], "apkGzSizes": [], "apkBrSizes": []}

        base_apk_path = os.path.join(pkg_path, "base.apk")
        assert os.path.isfile(base_apk_path)

        base_apk_signature = load_signature(base_apk_path)
        if (base_apk_signature not in pkg_signatures):
            raise Exception("unknown signature of " + base_apk_path + ", SHA-256: " + base_apk_signature)

        badging = subprocess.check_output(["aapt2", "dump", "badging", base_apk_path])

        lines = badging.split(b"\n")

        for kv in shlex.split(lines[0].decode()):
            if kv.startswith("versionName"):
                pkg_props["versionName"] = kv.split("=")[1]
            elif kv.startswith("versionCode"):
                assert pkg_props["versionCode"] == int(kv.split("=")[1])
            elif kv.startswith("name"):
                assert pkg_name == kv.split("=")[1]

        pkg_abis = set()

        for line in lines[1:-1]:
            kv = shlex.split(line.decode())
            if kv[0].startswith("application-label:"):
                pkg_props["label"] = kv[0].split(":")[1]
            elif kv[0].startswith("sdkVersion"):
                pkg_props["minSdk"] = int(kv[0].split(":")[1])
            elif kv[0].startswith("native-code"):
                abis = kv[1:]
                for abi in abis:
                    assert abi in all_abis
                assert len(pkg_abis) == 0
                pkg_abis.update(abis)

        assert pkg_props.get("minSdk") != None

        for key,value in load_props(pkg_path, "props").items():
            pkg_props[key] = value

        assert pkg_props["channel"] in ["alpha", "beta", "stable", "old"]

        for apk_name in sorted(filter(lambda n: n.endswith(".apk"), os.listdir(pkg_path))):
            apk_path = os.path.join(pkg_path, apk_name)

            apk_gz_path = apk_path + ".gz"
            apk_br_path = apk_path + ".br"

            assert os.path.getmtime(apk_path) == os.path.getmtime(apk_gz_path)
            assert os.path.getmtime(apk_path) == os.path.getmtime(apk_br_path)

            apk_hash_path = apk_path + ".sha256"

            if os.path.isfile(apk_hash_path):
                with open(apk_hash_path, "r") as f:
                    apk_hash = f.read()
            else:
                print("processing " + apk_path)

                if (load_signature(apk_path) != base_apk_signature):
                    # all apk splits must have the same signature
                    raise Exception("signature mismatch, apk: " + apk_path)

                badging = subprocess.check_output(["aapt2", "dump", "badging", apk_path])
                lines = badging.split(b"\n")
                apk_version_code = None
                for kv in shlex.split(lines[0].decode()):
                    if kv.startswith("versionCode"):
                        assert apk_version_code == None
                        apk_version_code = int(kv.split("=")[1])
                    elif kv.startswith("name"):
                        assert pkg_name == kv.split("=")[1]
                # all apk splits must have the same version code
                assert pkg_props["versionCode"] == apk_version_code

                hash = hashlib.new("sha256")
                with open(apk_path, "rb") as f:
                    hash.update(f.read())
                apk_hash = hash.hexdigest()
                with open(apk_hash_path, "w") as f:
                    f.write(apk_hash)

            pkg_props["apkHashes"].append(apk_hash)
            pkg_props["apkSizes"].append(int(os.path.getsize(apk_path)))
            pkg_props["apkGzSizes"].append(int(os.path.getsize(apk_gz_path)))
            pkg_props["apkBrSizes"].append(int(os.path.getsize(apk_br_path)))
            pkg_props["apks"].append(apk_name)

            name_parts = apk_name.split('.')
            if len(name_parts) >= 3:
                maybe_abi = name_parts[len(name_parts) - 2]
                if maybe_abi in abis_dict:
                    pkg_abis.add(abis_dict[maybe_abi])

        if len(pkg_abis) != 0:
            pkg_props["abis"] = list(pkg_abis)

        pkg_msg = "channel: " + pkg_props["channel"] + ", minSdk: " + str(pkg_props["minSdk"])
        maxSdk = pkg_props.get("maxSdk")
        if maxSdk != None:
            pkg_msg += ", maxSdk: " + maxSdk
        if len(pkg_abis) != 0:
            pkg_msg += "\nabis: " + ", ".join(pkg_abis)
        staticDeps = pkg_props.get("staticDeps")
        if staticDeps != None:
            pkg_msg += "\nstaticDeps: " + ", ".join(staticDeps)
        deps = pkg_props.get("deps")
        if deps != None:
            pkg_msg += "\ndeps: " + ", ".join(deps)
        pkg_msg += "\n"
        print(pkg_msg)

        # "old" release channel is for previous version(s), to prevent clients from getting
        # 404 errors when updating packages
        if pkg_props["channel"] == "old":
            continue

        package_variants[pkg_version] = pkg_props

    common_props["variants"] = remove_old_pkg_variants(package_variants)
    packages[pkg_name] = common_props


fsverity_certs = {}

fvc_version = 0
while True:
    fv_cert_der = "fsverity_cert." + str(fvc_version) + ".der"
    fv_cert_pem = "fsverity_cert." + str(fvc_version) + ".pem"
    fv_private_key = "fsverity_private_key." + str(fvc_version) + ".pem"

    if not os.path.isfile(fv_cert_der):
        break

    for pkg_name, common_props in packages.items():
        if "hasFsVeritySignatures" not in common_props:
            continue
        if not common_props["hasFsVeritySignatures"]:
            continue

        for pkg_version, pkg_props in common_props["variants"].items():
            pkg_path = packages_dir + "/" + pkg_name + "/" + pkg_version
            for apk in pkg_props["apks"]:
                apk_path = pkg_path + "/" + apk
                fsv_sig_path = apk_path + "." + str(fvc_version) + ".fsv_sig"

                if os.path.isfile(fsv_sig_path):
                    continue

                subprocess.run([
                    "fsverity", "sign",
                    apk_path, fsv_sig_path,
                    "--key=" + fv_private_key,
                    "--cert=" + fv_cert_pem,
                ]).check_returncode()

    with open(fv_cert_der, "rb") as f:
        fsverity_certs[str(fvc_version)] = base64.b64encode(f.read()).decode("utf-8")

    fvc_version += 1

metadata = {
    "time": int(datetime.datetime.now(datetime.UTC).timestamp()),
    "packages": packages,
    "fsVerityCerts": fsverity_certs,
}

metadata_prefix = "apps/metadata.1"
metadata_json = metadata_prefix + ".json"

with open(metadata_json, "w") as f:
    json.dump(metadata, f, separators=(',', ':'))

# sign metadata with all available key versions
key_version = 0
while True:
    private_key = "apps." + str(key_version) + ".sec"

    if not os.path.isfile(private_key):
        break

    metadata_json_sig = metadata_json + "." + str(key_version) + ".sig"
    metadata_sjson = metadata_prefix + "." + str(key_version) + ".sjson"

    subprocess.check_output(["signify", "-S", "-s", private_key, "-m", metadata_json, "-x", metadata_json_sig])

    with open(metadata_json_sig) as f:
        sig = f.read().splitlines()[1]

    shutil.copy(metadata_json, metadata_sjson)

    with open(metadata_sjson, "a") as f:
        f.write("\n" + sig + "\n")

    key_version += 1

