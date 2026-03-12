import os
import math
from collections import Counter


def calculate_entropy(data):
    if not data:
        return 0

    counter = Counter(data)
    length = len(data)

    entropy = 0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def extract_features_from_file(file_path):

    with open(file_path, "rb") as f:
        data = f.read()

    text = data.decode(errors="ignore")

    size = os.path.getsize(file_path)
    entropy = calculate_entropy(data)

    lines = text.splitlines()
    imports = text.count("import")
    functions = text.count("def ")
    suspicious_calls = (
        text.count("os.system")
        + text.count("subprocess")
        + text.count("eval")
        + text.count("exec")
    )

    printable_ratio = sum(c.isprintable() for c in text) / (len(text) + 1)

    # Simulated behavioral features
    millisecond = size % 1000
    state = len(lines) % 5
    usage_counter = imports + suspicious_calls
    prio = len(lines) % 140
    static_prio = prio + 5
    normal_prio = prio + 10
    policy = suspicious_calls
    vm_pgoff = size % 500
    vm_truncate_count = entropy
    task_size = size
    cached_hole_size = len(text)
    free_area_cache = printable_ratio * 100
    mm_users = imports
    map_count = functions
    hiwater_rss = size % 10000
    total_vm = size
    shared_vm = imports * 10
    exec_vm = suspicious_calls * 10
    reserved_vm = entropy * 10
    nr_ptes = size % 100
    end_data = size % 1000
    last_interval = len(lines)
    nvcsw = functions * 2
    nivcsw = suspicious_calls * 2
    min_flt = imports
    maj_flt = suspicious_calls
    fs_excl_counter = printable_ratio * 10
    lock = suspicious_calls
    utime = size % 200
    stime = entropy
    gtime = functions
    cgtime = imports
    signal_nvcsw = suspicious_calls

    features = [
        millisecond,
        state,
        usage_counter,
        prio,
        static_prio,
        normal_prio,
        policy,
        vm_pgoff,
        vm_truncate_count,
        task_size,
        cached_hole_size,
        free_area_cache,
        mm_users,
        map_count,
        hiwater_rss,
        total_vm,
        shared_vm,
        exec_vm,
        reserved_vm,
        nr_ptes,
        end_data,
        last_interval,
        nvcsw,
        nivcsw,
        min_flt,
        maj_flt,
        fs_excl_counter,
        lock,
        utime,
        stime,
        gtime,
        cgtime,
        signal_nvcsw
    ]

    return features