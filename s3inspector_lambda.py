import re
import boto3
import termcolor
import requests

from collections import defaultdict


s3 = boto3.resource('s3')
s3_client = boto3.client('s3')
sns = boto3.resource('sns')
platform_endpoint = sns.PlatformEndpoint('[arn:aws:sns:eu-west-1:051785622050:AWSTidy]')



explained = {
    'READ': 'readable',
    'WRITE': 'writable',
    'READ_ACP': 'permissions readable',
    'WRITE_ACP': 'permissions writeable',
    'FULL_CONTROL': 'Full Control'
}

groups_to_check = {
    'http://acs.amazonaws.com/groups/global/AllUsers': 'Everyone',
    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers': 'Authenticated AWS users'
}

SEP = '-' * 40


def check_acl(acl):
    dangerous_grants = defaultdict(list)
    for grant in acl.grants:
        grantee = grant['Grantee']
        if grantee['Type'] == 'Group' and grantee['URI'] in groups_to_check:
            dangerous_grants[grantee['URI']].append(grant['Permission'])
    public_indicator = True if dangerous_grants else False
    return public_indicator, dangerous_grants


def get_location(bucket_name):
    loc = s3_client.get_bucket_location(Bucket=bucket_name)["LocationConstraint"]
    if loc is None:
        loc = 'None(probably North Virginia)'
    return loc

def scan_bucket_urls(bucket_name):
    domain = 's3.amazonaws.com'
    access_urls = []
    urls_to_scan = [
        'https://{}.{}'.format(bucket_name, domain),
        'http://{}.{}'.format(bucket_name, domain),
        'https://{}/{}'.format(domain, bucket_name),
        'http://{}/{}'.format(domain, bucket_name)
    ]
    for url in urls_to_scan:
        content = requests.get(url).text
        if not re.search('Access Denied', content):
            access_urls.append(url)
    return access_urls


def lambda_handler(event, context):

        buckets = s3.buckets.all()
        try:
            bucketcount = 0
            for bucket in buckets:
                location = get_location(bucket.name)
                print(SEP)
                acl = bucket.Acl()
                public, grants = check_acl(acl)

                if public:
                    bucket_line = termcolor.colored(
                        bucket.name, 'blue', attrs=['bold'])
                    public_ind = termcolor.colored(
                        'PUBLIC!', 'red', attrs=['bold'])
                    termcolor.cprint('Bucket {}: {}'.format(
                        bucket_line, public_ind))
                    print('Location: {}'.format(location))
                    if grants:
                        for grant in grants:
                            permissions = grants[grant]
                            perm_to_print = []
                            for perm in permissions:
                                perm_to_print.append(explained[perm])
                            termcolor.cprint('Permission: {} by {}'.format(
                                termcolor.colored(
                                    ' & '.join(perm_to_print), 'red'),
                                termcolor.colored(groups_to_check[grant], 'red')))
                    urls = scan_bucket_urls(bucket.name)
                    print('URLs:')
                    if urls:
                        print('\n'.join(urls))
                    else:
                        print('Nothing found')
                    else:
                        bucket_line = termcolor.colored(
                            bucket.name, 'blue', attrs=['bold'])
                        public_ind = termcolor.colored(
                            'Not public', 'green', attrs=['bold'])
                        termcolor.cprint('Bucket {}: {}'.format(
                            bucket_line, public_ind))
                        print('Location: {}'.format(location))
                    bucketcount += 1
                if not bucketcount:
                    print('No buckets found')
                    termcolor.cprint(termcolor.colored('You are safe', 'green'))