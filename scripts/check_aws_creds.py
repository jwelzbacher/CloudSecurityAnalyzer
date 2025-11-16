#!/usr/bin/env python3
"""Quick script to check AWS credentials."""
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

try:
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    print('✓ AWS credentials configured')
    print(f'Account: {identity.get("Account")}')
    print(f'ARN: {identity.get("Arn")}')
    print(f'User ID: {identity.get("UserId")}')
except NoCredentialsError:
    print('✗ AWS credentials not found')
    print('\nPlease set credentials using one of:')
    print('1. Environment variables:')
    print('   export AWS_ACCESS_KEY_ID=your_key_id')
    print('   export AWS_SECRET_ACCESS_KEY=your_secret_key')
    print('   export AWS_DEFAULT_REGION=us-east-1')
    print('\n2. AWS credentials file (~/.aws/credentials)')
    print('3. IAM role (if running on EC2)')
except ClientError as e:
    print(f'✗ Error accessing AWS: {e}')
except Exception as e:
    print(f'✗ Unexpected error: {e}')

