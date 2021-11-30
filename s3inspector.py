import os
import re
import sys
import warnings

from datetime import datetime, timedelta
from os.path import expanduser
from collections import defaultdict

# ENTER VALID SNS RESOURCE ARN IF YOU WANT TO USE CODE AS LAMBDA.
SNS_RESOURCE_ARN = "******************************************************"
SEP = "-" * 40

EXPLAINED = {
    "READ": "readable",
    "WRITE": "writable",
    "READ_ACP": "permissions readable",
    "WRITE_ACP": "permissions writeable",
    "FULL_CONTROL": "Full Control"
}

GROUPS_TO_CHECK = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "Everyone",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "Authenticated AWS users"
}


def check_acl(acl):
    """
    Checks if the Access Control List is public.

    :param acl: Acl instance that describes bucket's.
    :return: Bucket's public indicator and dangerous grants parsed from acl instance.
    """
    dangerous_grants = defaultdict(list)
    for grant in acl.grants:
        grantee = grant["Grantee"]
        if grantee["Type"] == "Group" and grantee["URI"] in GROUPS_TO_CHECK:
            dangerous_grants[grantee["URI"]].append(grant["Permission"])
    public_indicator = True if dangerous_grants else False
    return public_indicator, dangerous_grants


def show_location_bucket(bucket_name, s3_client, report_path=None):
    """
    Show the bucket location in the console.

    :param bucket_name: Name of the bucket.
    :param s3_client: s3_client instance.
    :return: String with bucket's region.
    """
    loc = s3_client.get_bucket_location(
            Bucket=bucket_name)["LocationConstraint"]
    if loc is None:
        loc = "None(probably Northern Virginia)"

    add_to_output("Location: {}".format(loc), report_path)
    return loc


def scan_bucket_urls(bucket_name):
    """
    Scans standard bucket urls.
    Returns only publicly accessible urls.

    :param bucket_name: Name of the bucket.
    :return: List that contains publicly accessible urls.
    """
    domain = "s3.amazonaws.com"
    access_urls = []
    urls_to_scan = [
        "https://{}.{}".format(bucket_name, domain),
        "http://{}.{}".format(bucket_name, domain),
        "https://{}/{}".format(domain, bucket_name),
        "http://{}/{}".format(domain, bucket_name)
    ]
    warnings.filterwarnings("ignore")
    for url in urls_to_scan:
        try:
            content = requests.get(url).text
        except requests.exceptions.SSLError:
            continue
        if not re.search("Access Denied", content):
            access_urls.append(url)
    return access_urls


def add_to_output(msg, path=None):
    """
    Displays msg or writes it to file.

    :param msg: Message to handle.
    :param path: Path to lambda report file.
    """
    if path is not None:
        with open(path, "a") as f:
            text = re.sub('\033\\[\d+m', '', msg)
            f.write(text + '\n')
    # else:
    termcolor.cprint(msg)

def analyze_public_bucket(bucket, grants, report_path=None):
    """
    Analyses what and how the bucket is public. Sends results to defined output.

    :param bucket: s3 bucket resource instance.
    :param grants: s3 acl grants instance.
    :param report_path: Path to lambda report file.
    """
    if grants:
        for grant in grants:
            permissions = grants[grant]
            perm_to_print = [EXPLAINED[perm]
                            for perm in permissions]
            msg = "Permission: {} by {}".format(
                    termcolor.colored(" & ".join(perm_to_print), "red"),
                    termcolor.colored(GROUPS_TO_CHECK[grant], "red"))
            add_to_output(msg, report_path)
    urls = scan_bucket_urls(bucket.name)
    add_to_output("URLs:", report_path)
    if urls:
        add_to_output("\n".join(urls), report_path)
    else:
        add_to_output("Nothing found", report_path)


def show_bucket_info(bucket, bucket_ind, bucket_ind_color, report_path=None):
    """
    Analyses what and how the bucket is public. Sends results to defined output.

    :param bucket: s3 bucket resource instance.
    :param bucket_ind: A phrase to show in the output.
    :param bucket_ind_color: The color of the phrase.
    :param report_path: Path to lambda report file.
    """
    add_to_output(SEP, report_path)
    bucket_line = termcolor.colored(bucket.name, "blue", attrs=["bold"])
    public_ind = termcolor.colored(bucket_ind, bucket_ind_color, attrs=["bold"])

    msg = "Bucket {}: {}".format(bucket_line, public_ind)
    add_to_output(msg, report_path)


def analyze_buckets(s3, s3_client, report_path=None):
    """
    Analyses buckets permissions. Sends results to defined output.

    :param s3: s3 resource instance.
    :param s3_client: s3 client instance.
    :param report_path: Path to lambda report file.
    """
    buckets = s3.buckets.all()
    buckets_count = 0
    public_buckets = []

    for bucket in buckets:
        try:
            bucket_acl = bucket.Acl()
            public, grants = check_acl(bucket_acl)

            if public:
                show_bucket_info(bucket, "PUBLIC!", "red", report_path)
                show_location_bucket(bucket.name, s3_client, report_path)
                analyze_public_bucket(bucket, grants, report_path)
            else:
                show_bucket_info(bucket, "Not public", "green", report_path)
                show_location_bucket(bucket.name, s3_client, report_path)

        except botocore.exceptions.ClientError as e:
            show_bucket_info(bucket, "ACCESS ERROR", "red", report_path)
            add_to_output("Access Denied. I need a READ permission to access this S3 bucket.", report_path)
        buckets_count = 1
    if not buckets_count:
        add_to_output("No buckets found", report_path)
        msg = termcolor.colored("You are safe", "green")
        add_to_output(msg, report_path)


def install_and_import(pkg):
    """
    Installs latest versions of required packages.
    :param pkg: Package name.
    """
    import importlib
    try:
        importlib.import_module(pkg)
    except ImportError:
        import pip
        pip.main(["install", pkg])
    finally:
        globals()[pkg] = importlib.import_module(pkg)


def main():
    packages = ["boto3", "botocore", "termcolor", "requests"]
    for package in packages:
        install_and_import(package)

    s3 = boto3.resource("s3")
    s3_client = boto3.client("s3")
    analyze_buckets(s3, s3_client, "s3_result.txt")


if __name__ == "__main__":
    main()
