#!/usr/bin/env python3

import base64
import collections
import copy
import datetime
import filecmp
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import tomllib

from concurrent.futures import ThreadPoolExecutor
from functools import partial
from itertools import chain
from os import path
from pathlib import Path

def main():
    assert subprocess.call("./compress-apks") == 0

    packages_dir = "apps/packages"
    packages = {}

    with ThreadPoolExecutor() as executor:
        pkg_names = sorted(os.listdir(packages_dir))
        process_pkg_fn = partial(process_pkg, packages_dir)
        for pkg_result in maybe_parallel(executor, process_pkg_fn, pkg_names):
            pkg_name, common_props = pkg_result
            packages[pkg_name] = common_props

    fsverity_certs = {}

    fvc_version = 0
    while True:
        fv_cert_der = "fsverity_cert." + str(fvc_version) + ".der"
        fv_cert_pem = "fsverity_cert." + str(fvc_version) + ".pem"
        fv_private_key = "fsverity_private_key." + str(fvc_version) + ".pem"

        if not path.isfile(fv_cert_der):
            break

        if fvc_version > 0:
            raise Exception("having multiple fs-verity certificates is no longer supported")

        for pkg_name, common_props in packages.items():
            if "hasFsVeritySignatures" not in common_props:
                continue
            if not common_props["hasFsVeritySignatures"]:
                continue

            for pkg_version, pkg_props in common_props["variants"].items():
                pkg_path = packages_dir + "/" + pkg_name + "/" + pkg_version
                pkg_props["fsvSignatureSizes"] = []
                pkg_props["fsvSignatureHashes"] = []
                for apk in pkg_props["apks"]:
                    apk_path = pkg_path + "/" + apk
                    fsv_sig_path = apk_path + "." + str(fvc_version) + ".fsv_sig"

                    if not path.isfile(fsv_sig_path):
                        subprocess.run([
                            "fsverity", "sign",
                            apk_path, fsv_sig_path,
                            "--key=" + fv_private_key,
                            "--cert=" + fv_cert_pem,
                        ]).check_returncode()

                    fsv_sig_hash_path = fsv_sig_path + ".sha256"
                    if not path.isfile(fsv_sig_hash_path):
                        write_sha256(fsv_sig_path, fsv_sig_hash_path)

                    pkg_props["fsvSignatureSizes"].append(path.getsize(fsv_sig_path))
                    pkg_props["fsvSignatureHashes"].append(Path(fsv_sig_hash_path).read_text())

        with open(fv_cert_der, "rb") as f:
            fsverity_certs[str(fvc_version)] = base64.b64encode(f.read()).decode("utf-8")

        fvc_version += 1

    current_time = int(datetime.datetime.now(datetime.UTC).timestamp())
    metadata = {
        "time": current_time,
        "packages": packages,
        "fsVerityCerts": fsverity_certs,
    }

    metadata_prefix = "apps/metadata.1"
    if len(sys.argv) > 1 and sys.argv[1] == "staging":
        metadata_prefix = "apps/staging-metadata.1"

    metadata_json = metadata_prefix + ".json"

    with open(metadata_json, "w") as f:
        json.dump(metadata, f, separators=(',', ':'))

    # sign metadata with all available key versions
    key_version = 0
    while True:
        private_key = "apps." + str(key_version) + ".sec"

        if not path.isfile(private_key):
            break

        sig = signify(private_key, metadata_json)

        metadata_sjson = metadata_prefix + "." + str(key_version) + ".sjson"
        shutil.copy(metadata_json, metadata_sjson)

        with open(metadata_sjson, "a") as f:
            f.write("\n" + sig + "\n")

        key_version += 1

SINGLE_THREAD = os.getenv("SINGLE_THREAD", "0") == "1"

def maybe_parallel(executor, fn, *args):
    if SINGLE_THREAD:
        arg_tuples_list = list(zip(*args))
        res = []
        for arg_tuple in arg_tuples_list:
            res.append(fn(*arg_tuple))
        return res
    else:
        return list(executor.map(fn, *args))

def load_props(dir, name):
    file_path = path.join(dir, name + ".toml")
    if path.isfile(file_path):
        with open(file_path, "rb") as f:
            return tomllib.load(f)
    else:
        return {}

aapt2_limiter = threading.Semaphore(os.cpu_count())

def load_aapt2_badging(apk_path):
    cache_path = Path(apk_path + ".aapt2-badging")
    if cache_path.exists():
        return cache_path.read_text(encoding="utf-8")
    with aapt2_limiter:
        res = subprocess.check_output(["aapt2", "dump", "badging", apk_path]).decode()
    write_text(res, str(cache_path))
    return res

apksigner_limiter = threading.Semaphore(10) # apksigner runs in a JVM

def load_cert_digest(apk_path):
    cache_path = Path(apk_path + ".cert-digest")
    if cache_path.exists():
        return cache_path.read_text()

    with apksigner_limiter:
        apksigner_output = subprocess.check_output(["apksigner", "verify", "--print-certs", "--verbose", apk_path])
    cert_digest = None
    for line in apksigner_output.split(b'\n'):
        split = re.split(r"^V[^\s]+ Signer: certificate SHA-256 digest: ", line.decode())
        if (len(split) == 2):
            if (cert_digest is not None):
                if ("maxSdkVersion=" in line.decode()):
                    # ignore secondary maxSdk-restricted signers
                    continue
                # Intentionally don't support APKs that have more than one signer
                raise Exception(apk_path + " has more than one signer")
            cert_digest = split[1]

    if cert_digest is None:
        raise Exception("didn't find certificate of " + apk_path)
    write_text(cert_digest, str(cache_path))
    return cert_digest

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

    copy_dict = copy.deepcopy(orig_dict)

    ignored_props = [
        "apkBrHashes",
        "apkBrSizes",
        "apkDeltaHashes",
        "apkDeltaSizes",
        "apkDeltaSrcHashes",
        "apkGzSizes",
        "apkHashes",
        "apkSizes",
        "apks",
        "availableDeltaVersions",
        "description",
        "fsvSignatureHashes",
        "fsvSignatureSizes",
        "label",
        "releaseNotes",
        "v4SignatureHashes",
        "v4SignatureSizes",
        "versionCode",
        "versionName",
    ]

    for pkg_props in copy_dict.values():
        for k in ignored_props:
            pkg_props.pop(k, None)

    pkg_versions = sorted(orig_dict.keys(), key=int)

    # build a new dict that contains only those package versions that are not overriden by newer ones
    result = collections.OrderedDict()

    for i in range(0, len(pkg_versions)):
        pkg_version = pkg_versions[i]
        props = copy_dict[pkg_version]
        is_old = False
        for j in range(i + 1, len(copy_dict.keys())):
            if copy_dict[pkg_versions[j]] == props:
                # all relevant props are the same, pkg_version is overriden by pkg_versions[j]
                is_old = True
                break

        if not is_old:
            result[pkg_version] = orig_dict[pkg_version]

    return result

def file_sha256(file_path):
    with open(file_path, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()

def write_sha256(file_path, dst_path):
    sha256 = file_sha256(file_path)
    write_text(sha256, dst_path)

def write_text(text, dst_path):
    tmp_path = dst_path + ".write_text_tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.rename(tmp_path, dst_path)

def process_pkg_version(base_path, pkg_name, pkg_signatures, pkg_version):
    pkg_path = path.join(base_path, pkg_version)
    if not path.isdir(pkg_path):
        return None

    if SINGLE_THREAD: print("\nprocessing " + pkg_name + "/" + pkg_version)
    pkg_props = {"versionCode": int(pkg_version), "apks": [], "apkHashes": [],
                 "apkSizes": [], "apkGzSizes": [], "apkBrSizes": [], "apkBrHashes": []}

    base_apk_path = path.join(pkg_path, "base.apk")
    assert path.isfile(base_apk_path), base_apk_path

    base_apk_signature = load_cert_digest(base_apk_path)
    if (base_apk_signature not in pkg_signatures):
        raise Exception("unknown signature of " + base_apk_path + ", SHA-256: " + base_apk_signature)

    # This is needed to prevent App Store from attempting to install minSdk 31 version of this package on SDK 35+
    # devices, which have a separate minSdk 35+ package variant
    if pkg_name == "com.google.android.gms" and base_apk_signature == "7ce83c1b71f3d572fed04c8d40c5cb10ff75e6d87d9df6fbd53f0468c2905053":
        pkg_props["maxSdk"] = 34

    badging = load_aapt2_badging(base_apk_path)

    lines = badging.split("\n")

    for kv in shlex.split(lines[0]):
        if kv.startswith("versionName"):
            pkg_props["versionName"] = kv.split("=")[1]
        elif kv.startswith("versionCode"):
            assert pkg_props["versionCode"] == int(kv.split("=")[1]), base_apk_path
        elif kv.startswith("name"):
            assert pkg_name == kv.split("=")[1], base_apk_path

    pkg_abis = set()

    for line in lines[1:-1]:
        kv = shlex.split(line)
        if kv[0].startswith("application-label:"):
            pkg_props["label"] = kv[0].split(":")[1]
        elif kv[0].startswith("minSdkVersion"):
            pkg_props["minSdk"] = int(kv[0].split(":")[1])
        elif kv[0].startswith("native-code"):
            abis = kv[1:]
            for abi in abis:
                assert abi in all_abis, base_apk_path
            assert len(pkg_abis) == 0, base_apk_path
            pkg_abis.update(abis)
        elif kv[0].startswith("alt-native-code"):
            abis = kv[1:]
            for abi in abis:
                assert abi in all_abis, base_apk_path
                pkg_abis.add(abi)

    assert pkg_props.get("minSdk") != None, pkg_path

    for key,value in load_props(pkg_path, "channel").items():
        pkg_props[key] = value

    for key,value in load_props(pkg_path, "props").items():
        pkg_props[key] = value

    assert pkg_props["channel"] in ["alpha", "beta", "stable", "old"], pkg_path

    has_v4_sigs = None

    for apk_name in sorted(filter(lambda n: n.endswith(".apk"), os.listdir(pkg_path))):
        apk_path = path.join(pkg_path, apk_name)

        apk_gz_path = apk_path + ".gz"
        apk_br_path = apk_path + ".br"

        assert path.getmtime(apk_path) == path.getmtime(apk_gz_path), apk_path
        assert path.getmtime(apk_path) == path.getmtime(apk_br_path), apk_path

        apk_idsig_path = apk_path + ".idsig"
        if path.isfile(apk_idsig_path):
            if has_v4_sigs is False:
                # at least one previously encountered APK didn't have v4 sig
                raise Exception("one or more APK is missing a v4 signature: " + pkg_path)
            apk_idsig_hash_path = apk_idsig_path + ".sha256"
            if not path.isfile(apk_idsig_hash_path):
                write_sha256(apk_idsig_path, apk_idsig_hash_path)

            pkg_props.setdefault("v4SignatureSizes", []).append(path.getsize(apk_idsig_path))
            pkg_props.setdefault("v4SignatureHashes", []).append(Path(apk_idsig_hash_path).read_text())
            has_v4_sigs = True
        else:
            if has_v4_sigs:
                raise Exception("v4 signature is missing for " + apk_path)
            has_v4_sigs = False

        apk_hash_path = apk_path + ".sha256"

        if not path.isfile(apk_hash_path):
            if SINGLE_THREAD: print("processing " + apk_path)

            if (load_cert_digest(apk_path) != base_apk_signature):
                # all apk splits must have the same signature
                raise Exception("signature mismatch, apk: " + apk_path)

            badging = load_aapt2_badging(apk_path)
            lines = badging.split("\n")
            apk_version_code = None
            for kv in shlex.split(lines[0]):
                if kv.startswith("versionCode"):
                    assert apk_version_code == None, apk_path
                    apk_version_code = int(kv.split("=")[1])
                elif kv.startswith("name"):
                    assert pkg_name == kv.split("=")[1], apk_path
            # all apk splits must have the same version code
            assert pkg_props["versionCode"] == apk_version_code, apk_path
            write_sha256(apk_path, apk_hash_path)

        pkg_props["apkHashes"].append(Path(apk_hash_path).read_text())
        pkg_props["apkSizes"].append(int(path.getsize(apk_path)))
        pkg_props["apkGzSizes"].append(int(path.getsize(apk_gz_path)))
        pkg_props["apkBrSizes"].append(int(path.getsize(apk_br_path)))
        apk_br_hash_path = apk_br_path + ".sha256"
        if not path.isfile(apk_br_hash_path):
            write_sha256(apk_br_path, apk_br_hash_path)
        pkg_props["apkBrHashes"].append(Path(apk_br_hash_path).read_text())
        pkg_props["apks"].append(apk_name)

        name_parts = apk_name.split('.')
        if len(name_parts) >= 3:
            maybe_abi = name_parts[len(name_parts) - 2]
            if maybe_abi in abis_dict:
                pkg_abis.add(abis_dict[maybe_abi])

    if has_v4_sigs:
        pkg_props["hasV4Signatures"] = True

    if len(pkg_abis) != 0:
        pkg_props["abis"] = sorted(pkg_abis)

    if SINGLE_THREAD:
        pkg_msg = "channel: " + pkg_props["channel"] + ", minSdk: " + str(pkg_props["minSdk"])
        maxSdk = pkg_props.get("maxSdk")
        if maxSdk != None:
            pkg_msg += ", maxSdk: " + str(maxSdk)
        if len(pkg_abis) != 0:
            pkg_msg += "\nabis: " + ", ".join(pkg_abis)
        staticDeps = pkg_props.get("staticDeps")
        if staticDeps != None:
            pkg_msg += "\nstaticDeps: " + ", ".join(staticDeps)
        print(pkg_msg)

    # "old" release channel is for previous version(s), to prevent clients from getting
    # 404 errors when updating packages
    if pkg_props["channel"] == "old":
        return None

    return pkg_version, pkg_props

ina_limiter = threading.Semaphore(os.cpu_count())

def handle_deltas_apk(prev_version_dir, prev_version_code, current_version_dir, apk_name):
    prev_apk = path.join(prev_version_dir, apk_name)
    if not path.isfile(prev_apk):  # new version added a split
        return "", 0, ""

    ina_patch = path.join(current_version_dir,
                             apk_name + "." + str(prev_version_code) + ".ina")
    ina_patch_hash = ina_patch + ".sha256"
    skip_ina_marker = ina_patch + ".skip"
    if not path.isfile(ina_patch_hash) and not path.isfile(skip_ina_marker):
        current_apk = path.join(current_version_dir, apk_name)
        ina_patch_tmp = ina_patch + ".tmp"

        with ina_limiter:
            if SINGLE_THREAD:
                print("running ina diff for " + apk_name)
            else:
                path_parts = current_version_dir.split("/")
                pkg_name = path_parts[len(path_parts) - 2]
                current_version = path_parts[len(path_parts) - 1]
                print("running ina diff " + pkg_name + " " + str(prev_version_code) + " " + current_version + " " + apk_name)
            subprocess.run(
                ["ina", "diff", prev_apk, current_apk, ina_patch_tmp]).check_returncode()
            ina_test_path = ina_patch + ".test"
            subprocess.run(
                ["ina", "patch", prev_apk, ina_patch_tmp, ina_test_path]).check_returncode()

        if not filecmp.cmp(current_apk, ina_test_path, shallow=False):
            raise Exception("ina patch application failed for " + current_apk)
        os.remove(ina_test_path)

        with open(ina_patch_tmp, "r") as f:
            os.fsync(f.fileno())
        os.rename(ina_patch_tmp, ina_patch)

        patch_size = path.getsize(ina_patch)
        br_size = path.getsize(current_apk + ".br")
        ratio_str = "ina/apk.br ratio is " + f"{(patch_size / br_size):.2f}" + " (" + str(
            patch_size) + "/" + str(br_size) + ")"
        if SINGLE_THREAD: print(ratio_str)
        if patch_size >= br_size:
            os.remove(ina_patch)
            write_text(ratio_str, skip_ina_marker)
        else:
            write_text(file_sha256(ina_patch), ina_patch_hash)

    if path.isfile(skip_ina_marker):
        if SINGLE_THREAD: print("skipping ina for " + apk_name + " since " + Path(
            skip_ina_marker).read_text())
        return "", 0, ""
    else:
        return Path(prev_apk + ".sha256").read_text(), path.getsize(ina_patch), Path(ina_patch_hash).read_text()

def handle_deltas_pkg(pkg_container_path, current_version, current_version_code, current_version_dir, prev_version):
    prev_version_code = prev_version["versionCode"]
    if SINGLE_THREAD: print("processing " + str(prev_version_code) + " -> " + current_version_code + " deltas")
    prev_version_dir = path.join(pkg_container_path, str(prev_version_code))
    deltas_src_sha256 = []
    delta_sizes = []
    deltas_sha256 = []
    handle_deltas_apk_fn = partial(handle_deltas_apk, prev_version_dir, prev_version_code, current_version_dir)

    with ThreadPoolExecutor() as executor:
        for res in maybe_parallel(executor, handle_deltas_apk_fn, current_version["apks"]):
            src_sha256, delta_size, delta_sha256 = res
            deltas_src_sha256.append(src_sha256)
            delta_sizes.append(delta_size)
            deltas_sha256.append(delta_sha256)

    return prev_version_code, deltas_src_sha256, delta_sizes, deltas_sha256

def handle_deltas_group(pkg_container_path, pkg_name, dst_version, src_versions):
    dst_version_code = str(dst_version["versionCode"])
    dst_version_dir = path.join(pkg_container_path, dst_version_code)
    delta_version_codes = []
    deltas_src_sha256 = []
    delta_sizes = []
    deltas_sha256 = []

    handle_deltas_pkg_fn = partial(handle_deltas_pkg, pkg_container_path, dst_version, dst_version_code, dst_version_dir)

    with ThreadPoolExecutor() as executor:
        # generate deltas for at most 2 previous versions
        for res in maybe_parallel(executor, handle_deltas_pkg_fn, src_versions):
            version_code, src_hashes, sizes, hashes = res
            delta_version_codes.append(version_code)
            deltas_src_sha256.append(src_hashes)
            delta_sizes.append(sizes)
            deltas_sha256.append(hashes)

    dst_version["availableDeltaVersions"] = delta_version_codes
    dst_version["apkDeltaSrcHashes"] = list(chain.from_iterable(zip(*deltas_src_sha256)))
    dst_version["apkDeltaSizes"] = list(chain.from_iterable(zip(*delta_sizes)))
    dst_version["apkDeltaHashes"] = list(chain.from_iterable(zip(*deltas_sha256)))

def process_deltas(pkg_container_path, pkg_name, dst_versions, package_variants):
    versions = list(reversed(package_variants.values()))  # newest first

    def is_compatible(a, b):
        abis_match = a.get("abis") is None or b.get("abis") is None or a["abis"] == b["abis"]
        return abis_match and a.get("maxSdk") == b.get("maxSdk")

    dsts = []
    srcs = []

    for idx, version in enumerate(versions):
        if version["versionCode"] in dst_versions:
            # generate deltas for at most 2 previous versions
            src_versions = [v for v in versions[idx + 1:] if is_compatible(version, v)][:2]
            if src_versions:
                dsts.append(version)
                srcs.append(src_versions)

    with ThreadPoolExecutor() as executor:
        maybe_parallel(executor, partial(handle_deltas_group, pkg_container_path, pkg_name), dsts, srcs)

def process_pkg(packages_dir, pkg_name):
    pkg_container_path = path.join(packages_dir, pkg_name)
    common_props = load_props(pkg_container_path, "common-props")

    icon_path = path.join(pkg_container_path, "icon.webp")
    if path.isfile(icon_path):
        common_props["iconType"] = "webp"
        common_props["iconSha256"] = file_sha256(icon_path)
        common_props["iconSize"] = path.getsize(icon_path)

    pkg_signatures = common_props["signatures"]
    package_variants = collections.OrderedDict()

    process_pkg_version_fn = partial(process_pkg_version, pkg_container_path, pkg_name, pkg_signatures)
    pkg_versions = sorted(filter(lambda n: n.isdigit(), os.listdir(pkg_container_path)), key=int)

    with ThreadPoolExecutor() as executor:
        for res in maybe_parallel(executor, process_pkg_version_fn, pkg_versions):
            if (res != None):
                ver, props = res
                package_variants[ver] = props

    pruned_package_variants = remove_old_pkg_variants(package_variants)
    process_deltas(pkg_container_path, pkg_name, {int(v) for v in pruned_package_variants.keys()}, package_variants)
    common_props["variants"] = pruned_package_variants

    return pkg_name, common_props


def signify(private_key, file_path):
    return subprocess.check_output(["signify", "-S", "-s", private_key, "-m", file_path, "-x", "-"]
                                  ).split(b'\n')[1].decode()

if __name__ == "__main__":
    sys.exit(main())
