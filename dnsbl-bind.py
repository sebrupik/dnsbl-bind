import json
import os
import random
import re
import string
import sys

OUTPUT_TYPE = "RPZ"

AGG_FILE="aggregate_zones.conf"
INPUT_PATH = "./input_files"
ZONE_FILE = "blockeddomains.zone.dns"
ZONE_FILE_PATH = "/usr/local/etc/namedb"
ZONE_FILE_PATH_OUTPUT = "/usr/local/etc/namedb/blocked_zones"
ZONE_FILE_LINE = "zone {0} {{ type master;  file \"{1}/{2}\"; }};\n"
ZONE_FILE_LINE_02 = "include \"{0}\";"

RPZ_CONFIG_BLOCK_01 = "response-policy {{ zone \"{0}\"; }};\n"
RPZ_CONFIG_BLOCK_02 = "zone \"{0}\" {{\n    type master;\n    file \"{1}\";\n}};\n"
RPZ_FILE_LINE = "{0} CNAME .\n"

REGEX_BL = [r"^(?P<domain>.*?)\s(?P<tag>[#].*)$",                       # '206ads.com #Advertising Unknown'
            r"^(?P<ip>(\d{1,3}.){3}(\d{1,3}))\s(?P<domain>.*)$",  # '0.0.0.0 www.ocsp.apple.com'
            r"^(?P<domain>.*[.]\S*)$",                                  # '00z70az77mnsa-00swj1zzprh.com'
            r"^(::)\d?\s(?P<domain>.\S*)$"]                              # ':: 2606:4700:30::6818:754a'


def gen_uid():
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(6))


def parse_input_directory(path, file, blocked_domains):
    forbidden = ["localhost"]
    uid = gen_uid()
    with open("{0}/{1}".format(path, file), "r", encoding="ISO-8859-1") as f:
        blocked_domains["uids"][uid] = file
        for line in f:
            if line[0] is not "#" and len(line.strip()) > 0:
                matched = False
                for r in REGEX_BL:
                    m = re.search(r, line)
                    if m:
                        matched = True
                        domains = m.group("domain").split(" ")
                        for d in domains:
                            if d.lower() not in blocked_domains["all"] and d.lower() not in forbidden:
                                blocked_domains["all"][d.lower()] = uid
                        break
                if not matched:
                    print("no regex match for: {0} in {1}".format(line, file))

    return blocked_domains


def output_blocked_domains(output_path, blocked_domains, output_type):
    sorted_domains = dict()
    for d in blocked_domains["all"]:
        if blocked_domains["all"][d] not in sorted_domains:
            sorted_domains[blocked_domains["all"][d]] = []
        sorted_domains[blocked_domains["all"][d]].append(d)

    for uid in sorted_domains:
        output_zones(output_path, blocked_domains, sorted_domains, uid, output_type)

    output_agg_file(output_path, sorted_domains.keys(), output_type)


def output_zones(output_path, blocked_domains, sorted_domains, uid, output_type):
    with open("{0}/{1}".format(output_path, uid), "w") as f:
        print("Writing {0}, source {1} with {2} items".format(uid, blocked_domains["uids"][uid],
                                                              len(sorted_domains[uid])))
        f.write("# {0}\n".format(blocked_domains["uids"][uid]))
        for domain in sorted_domains[uid]:
            if len(domain.strip()) > 0:
                if output_type == "PLAIN_ZONE":
                    f.write(ZONE_FILE_LINE.format(domain, ZONE_FILE_PATH, ZONE_FILE))
                elif output_type == "RPZ":
                    f.write(RPZ_FILE_LINE.format(domain))


def output_agg_file(output_path, blocked_domain_file_list, output_type):
    with open("{0}/{1}".format(output_path, AGG_FILE), "w") as f:
        if output_type == "PLAIN_ZONE":
            # blah
            for bd in blocked_domain_file_list:
                f.write(ZONE_FILE_LINE_02.format("{0}/{1}".format(output_path, bd)))
        elif output_type == "RPZ":
            rpz_block = ""

            f.write("options {\n")
            for bd in blocked_domain_file_list:
                f.write(RPZ_CONFIG_BLOCK_01.format(bd))

                rpz_block = rpz_block+RPZ_CONFIG_BLOCK_02.format(bd, "{0}/{1}".format(output_path, bd))
            f.write("};\n\n")

            f.write(rpz_block)


def load_config(config_path):
    with open(config_path, "r") as json_file:
        c = json.load(json_file)

        return c


def main():
    blocked_domains = dict()
    blocked_domains["uids"] = dict()
    blocked_domains["all"] = dict()

    file_list = os.listdir(INPUT_PATH)
    for file in file_list:
        blocked_domains = parse_input_directory(INPUT_PATH, file, blocked_domains)

    print("We parsed {0} input files".format(len(blocked_domains)))
    print("We parsed unique {0} domains".format(len(blocked_domains["all"])))

    output_blocked_domains(ZONE_FILE_PATH_OUTPUT, blocked_domains, OUTPUT_TYPE)


if __name__ == "__main__":
    print(len(sys.argv))
    if len(sys.argv) == 5:
        ZONE_FILE_PATH = sys.argv[1]
        ZONE_FILE_PATH_OUTPUT = sys.argv[2]
        INPUT_PATH = sys.argv[3]

        if sys.argv[4] == "plain":
            OUTPUT_TYPE = "PLAIN_ZONE"
        elif sys.argv[4] == "rpz":
            OUTPUT_TYPE = "RPZ"

        print("got some arguments!")
    main()
