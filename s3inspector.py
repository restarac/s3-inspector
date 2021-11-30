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


def get_s3_obj(is_lambda=False):
    """
    Gets and returns s3 resource and client.

    :param is_lambda: If True - defines that code has been launched as lambda.
    :return: s3 resource and client instances.
    """
    s3 = boto3.resource("s3")
    s3_client = boto3.client("s3")
    return s3, s3_client


def tidy(path):
    """
    Removes file described by path.

    :param path: Path to file needs to be removed.
    """
    try:
        os.remove(path)
    except OSError:
        pass


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


def get_location(bucket_name, s3_client):
    """
    Returns the bucket location.

    :param bucket_name: Name of the bucket.
    :param s3_client: s3_client instance.
    :return: String with bucket's region.
    """
    loc = s3_client.get_bucket_location(
            Bucket=bucket_name)["LocationConstraint"]
    if loc is None:
        loc = "None(probably Northern Virginia)"
    return loc


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
            f.write(msg + '\n')
    else:
        termcolor.cprint(msg)


def analyze_buckets(s3, s3_client, report_path=None):
    """
    Analyses buckets permissions. Sends results to defined output.

    :param s3: s3 resource instance.
    :param s3_client: s3 client instance.
    :param report_path: Path to lambda report file.
    """
    buckets = s3.buckets.all()
    buckets_count = 0

    for bucket in buckets:
        try:
            location = get_location(bucket.name, s3_client)
            add_to_output(SEP, report_path)
            bucket_acl = bucket.Acl()
            public, grants = check_acl(bucket_acl)

            if public:
                bucket_line = termcolor.colored(bucket.name, "blue", attrs=["bold"])
                public_ind = termcolor.colored("PUBLIC!", "red", attrs=["bold"])
                msg = "Bucket {}: {}".format(bucket_line, public_ind)
                add_to_output(msg, report_path)
                add_to_output("Location: {}".format(location), report_path)

                if grants:
                    for grant in grants:
                        permissions = grants[grant]
                        perm_to_print = [EXPLAINED[perm]
                                         for perm in permissions]
                        if report_path:
                            msg = "Permission: {} by {}".format(" & ".join(perm_to_print),
                                                                (GROUPS_TO_CHECK[grant]))
                        else:
                            msg = "Permission: {} by {}".format(
                                    termcolor.colored(
                                            " & ".join(perm_to_print), "red"),
                                    termcolor.colored(GROUPS_TO_CHECK[grant], "red"))
                        add_to_output(msg, report_path)
                urls = scan_bucket_urls(bucket.name)
                add_to_output("URLs:", report_path)
                if urls:
                    add_to_output("\n".join(urls), report_path)
                else:
                    add_to_output("Nothing found", report_path)
            else:
                bucket_line = termcolor.colored(bucket.name, "blue", attrs=["bold"])
                public_ind = termcolor.colored("Not public", "green", attrs=["bold"])
                msg = "Bucket {}: {}".format(bucket_line, public_ind)
                add_to_output(msg, report_path)
                add_to_output("Location: {}".format(location), report_path)
        except botocore.exceptions.ClientError as e:
            add_to_output(SEP, report_path)
            bucket_line = termcolor.colored(bucket.name, "blue", attrs=["bold"])
            public_ind = termcolor.colored("ACCESS ERROR", "red", attrs=["bold"])
            msg = "Bucket {}: {}".format(bucket_line, public_ind)
            add_to_output(msg, report_path)
            add_to_output("""Access Denied. I need a READ permission to access this S3 bucket.""", report_path)
        buckets_count += 1
    if buckets_count:
        add_to_output("No buckets found")
        msg = termcolor.colored("You are safe", "green")
        add_to_output(msg, report_path)

def send_report(path):
    """
    Sends report generated by script via sns service.

    :param path: Path to report file.
    """
    sns = boto3.resource("sns")
    platform_endpoint = sns.PlatformEndpoint(SNS_RESOURCE_ARN)
    today = datetime.now() + timedelta(days=1)
    with open(path, "r") as f:
        rts = f.read()
    platform_endpoint.publish(
        Message=rts,
        Subject="S3 Monitor Report: " + str(today),
        MessageStructure="string"
    )

# def resolve_exception(exception, report_path=None):
#     """
#     Handles exceptions that appears during bucket check run.

#     :param exception: Exception instance.
#     :param report_path: Path to report path.
#     """
#     msg = str(exception)
#     if "InvalidAccessKeyId" in msg and "does not exist" in msg:
#         add_to_output("The Access Key ID you provided does not exist", report_path)
#         add_to_output("Please, make sure you give me the right credentials", report_path)
#     elif "SignatureDoesNotMatch" in msg:
#         add_to_output("The Secret Access Key you provided is incorrect", report_path)
#         add_to_output("Please, make sure you give me the right credentials", report_path)
#     elif "AccessDenied" in msg:
#         add_to_output("""Access Denied. I need permission to access S3.""", report_path)
#     else:
#         add_to_output("""{}
# Check your credentials in ~/.aws/credentials file

# The user also has to have programmatic access enabled
# If you didn't enable it(when you created the account), then:
# 1. Click the user
# 2. Go to "Security Credentials" tab
# 3. Click "Create Access key"
# 4. Use these credentials""".format(msg), report_path)


def main():
    if sys.version[0] == "3":
        raw_input = input
    packages = ["boto3", "botocore", "termcolor", "requests"]
    for package in packages:
        install_and_import(package)
    s3, s3_client = get_s3_obj()
    analyze_buckets(s3, s3_client)


if __name__ == "__main__":
    main()
