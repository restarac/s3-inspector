<p align="center">
   <img alt="S3 Inspector" src="https://github.com/clario-tech/s3-inspector/blob/logo/logo.png" width="400"/>
</p>

Tool to check AWS S3 bucket permissions.

This is a fork from https://github.com/clario-tech/s3-inspector created to work better on terminals.

***Will be created a file with the results in case there are many bucket in your account you can check this file***

## What it does
 - Checks all your buckets for public access
 - For every bucket gives you the report with:
   - Indicator if your bucket is public or not
   - Permissions for your bucket if it is public
   - List of URLs to access your bucket (non-public buckets will return Access Denied) if it is public

## Prerequisites
**Compatible** with Linux, MacOS and Windows, python 3.

### (Recomended) Use AWS environment variables
 - **Set AWS environment variables**
```
export AWS_ACCESS_KEY_ID="ASIA...NOPJ"
export AWS_SECRET_ACCESS_KEY="Gdd...icc"
```
Optionally you can set
```
export AWS_SESSION_TOKEN="IQoJb3JpZ2luX2Vj.....QHZDsPHxftf0NE="
```
 - After that run the script in the same shell you set this envs

### Use existing configured IAM User
 - **use your existing credentials or profile** if you have a file `~/.aws/credentials` like this:
```
[default]
aws_access_key_id = <your access key ID goes here>
aws_secret_access_key = <your secret_access_key goes here>
[my_profile_name]
aws_access_key_id = <your access key ID goes here>
aws_secret_access_key = <your secret_access_key goes here>
```
 - and pass the profile name or leave blank for `default` when requested:
```
python s3inspector.py
Enter your AWS profile name [default]:
```

### Create a new IAM User
 - **Create IAM user with AmazonS3ReadOnly policy attached**
   - Go to IAM (https://console.aws.amazon.com/iam/home)
   - Click "Users" on the left hand side menu
   - Click "Add user"
   - Fill in user name and check **Programmatic access**
   - Click "Next: Permissions"
   - Click "Attach existing policies directly"
   - Check **AmazonS3ReadOnly** policy
   - Click "Next: Review"
   - Click "Create user"
   - **Copy the credentials**
     - **Access key ID**
     - **Secret access key**
 - **Create ~/.aws/credentials file or paste the credentials in when you run the script**
   - Put the credentials you copied in the previous step here in this format:
```
[default]
aws_access_key_id = <your access key ID goes here>
aws_secret_access_key = <your secret_access_key goes here>
```

## Usage
`python s3inspector.py`

## Report example
![Sample report screenshot](https://github.com/clario-tech/s3-inspector/blob/screenshot/samplerun.png "Sample report screenshot")
