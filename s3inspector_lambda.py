import re
import boto3
import botocore
import os
import botocore.vendored.requests as requests
from datetime import datetime, timedelta
from collections import defaultdict

s3 = boto3.resource('s3')
s3_client = boto3.client('s3')
sns = boto3.resource('sns')
sts = boto3.client('sts')

account_id=sts.get_caller_identity()["Account"]

platform_endpoint = sns.PlatformEndpoint('arn:aws:sns:eu-west-1:'+account_id+':S3Monitor')
today = datetime.now() + timedelta(days=1)

groups_to_check = {
    'http://acs.amazonaws.com/groups/global/AllUsers': 'Everyone',
    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers': 'Authenticated AWS users'
}

def check_acl(acl):
    dangerous_grants = defaultdict(list)
    for grant in acl.grants:
        grantee = grant['Grantee']
        if grantee['Type'] == 'Group' and grantee['URI'] in groups_to_check:
            dangerous_grants[grantee['URI']].append(grant['Permission'])
    public_indicator = True if dangerous_grants else False
    return public_indicator, dangerous_grants


def get_location(bucket_name):
    loc = s3_client.get_bucket_location(
        Bucket=bucket_name)['LocationConstraint']
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

def tidy_tmp():
    try:
        os.remove('/tmp/report.txt')
    except OSError:
        pass


def lambda_handler(event,context):
    
    SEP = '-' * 40
    explained = {
        'READ': 'readable',
        'WRITE': 'writable',
        'READ_ACP': 'permissions readable',
        'WRITE_ACP': 'permissions writeable',
        'FULL_CONTROL': 'Full Control'
    }
    
    bucket_list = []
    buckets = s3.buckets.all()
    tidy_tmp()
    report = open('/tmp/report.txt', 'a')
    try:
        bucketcount = 0
        for bucket in buckets:
            location = get_location(bucket.name)
            print >>report, (SEP)
            acl = bucket.Acl()
            public, grants = check_acl(acl)

            if public:
                public_ind = 'PUBLIC!'
                print >>report, ('Bucket {}: {}'.format(bucket.name, public_ind))
                print >>report, ('Location: {}'.format(location))
                if grants:
                    for grant in grants:
                        permissions = grants[grant]
                        perm_to_print = [explained[perm] for perm in permissions]
                        print >>report, ('Permission: {} by {}'.format(' & '.join(perm_to_print),(groups_to_check[grant])))
                urls = scan_bucket_urls(bucket.name)
                print >>report, ('URLs:')
                if urls:
                    print >>report, ('\n'.join(urls))
                else:
                    print >>report, ('Nothing found')
            else:
                public_ind = 'Not public'
                print >>report, ('Bucket {}: {}'.format(bucket.name, public_ind))
                print >>report, ('Location: {}'.format(location))
            bucketcount += 1
        report.close()
        if not bucketcount:
            print >>report, ('No buckets found')
            print >>report, ('You are safe')
            report.close()
    except botocore.exceptions.ClientError as e:
        msg = str(e)
        if 'AccessDenied' in msg:
            print >>report, ('''Access Denied
I need permission to access S3
Check if the Lambda Execution Policy at least has AmazonS3ReadOnlyAccess, SNS Publish & Lambda Execution policies attached

To find the list of policies attached to your user, perform these steps:
1. Go to IAM (https://console.aws.amazon.com/iam/home)
2. Click "Roles" on the left hand side menu
3. Click the role lambda is running with 
4. Here it is
''')
            report.close()
        else:
            print >>report, ('''{}
Something has gone very wrong, please check the Cloudwatch Logs Stream for further details'''.format(msg))
            report.close()


    report = open('/tmp/report.txt', 'r') 
    rts = report.read()
    report.close()

    platform_endpoint.publish(
        Message=rts,
        Subject='S3 Monitor Report: ' +str(today),
        MessageStructure='string',
    )

    tidy_tmp()
