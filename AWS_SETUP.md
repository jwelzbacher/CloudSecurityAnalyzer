# AWS Environment Setup Guide for CS-Kit

This guide will help you set up an AWS development environment for testing CS-Kit security scans.

## Prerequisites

1. **AWS Account**: You need an active AWS account
2. **AWS CLI**: Install and configure AWS CLI (optional, for manual setup)
3. **Python 3.12+**: Required for the setup scripts
4. **boto3**: Python AWS SDK (`pip install boto3`)

## IAM Setup

You'll need to create an IAM user with appropriate permissions. There are two scenarios:

### Option 1: Separate Users (Recommended)

Create two IAM users:
1. **Setup User**: For creating/managing resources (needs write permissions)
2. **Scan User**: For running Prowler scans (needs read-only permissions)

### Option 2: Single User

Use one IAM user with both setup and scan permissions (less secure, but simpler for development).

## IAM Permissions Required

### For Setup (Creating Resources)

The setup script needs permissions to create:
- VPCs, Subnets, Internet Gateways, Route Tables
- Security Groups
- EC2 Instances

**Recommended Policy**: Attach the `AmazonEC2FullAccess` managed policy, or use this custom policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:*",
                "iam:PassRole"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

**Note**: For production, use least-privilege principles and restrict resources with tags.

### For Scanning (Prowler)

Prowler requires read-only access to most AWS services. The recommended approach is to use Prowler's built-in IAM policy.

**Recommended**: Use Prowler's SecurityAudit policy or attach this policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "acm:Describe*",
                "acm:List*",
                "apigateway:GET",
                "autoscaling:Describe*",
                "cloudformation:Describe*",
                "cloudformation:Get*",
                "cloudformation:List*",
                "cloudfront:Get*",
                "cloudfront:List*",
                "cloudtrail:Describe*",
                "cloudtrail:Get*",
                "cloudtrail:LookupEvents",
                "cloudwatch:Describe*",
                "cloudwatch:Get*",
                "cloudwatch:List*",
                "codebuild:BatchGet*",
                "codebuild:List*",
                "config:Describe*",
                "config:Get*",
                "config:List*",
                "dynamodb:Describe*",
                "dynamodb:List*",
                "ec2:Describe*",
                "ec2:Get*",
                "ecr:Describe*",
                "ecr:Get*",
                "ecr:List*",
                "ecs:Describe*",
                "ecs:List*",
                "eks:Describe*",
                "eks:List*",
                "elasticache:Describe*",
                "elasticache:List*",
                "elasticloadbalancing:Describe*",
                "es:Describe*",
                "es:List*",
                "events:Describe*",
                "events:List*",
                "firehose:Describe*",
                "firehose:List*",
                "guardduty:Describe*",
                "guardduty:Get*",
                "guardduty:List*",
                "iam:GenerateCredentialReport",
                "iam:GenerateServiceLastAccessedDetails",
                "iam:Get*",
                "iam:List*",
                "kms:Describe*",
                "kms:Get*",
                "kms:List*",
                "lambda:Get*",
                "lambda:List*",
                "logs:Describe*",
                "logs:Get*",
                "logs:TestMetricFilter",
                "rds:Describe*",
                "rds:List*",
                "redshift:Describe*",
                "redshift:ViewQueriesInConsole",
                "route53:Get*",
                "route53:List*",
                "route53domains:Get*",
                "route53domains:List*",
                "s3:Get*",
                "s3:List*",
                "secretsmanager:Describe*",
                "secretsmanager:Get*",
                "secretsmanager:List*",
                "shield:Describe*",
                "shield:Get*",
                "shield:List*",
                "sns:Get*",
                "sns:List*",
                "sqs:Get*",
                "sqs:List*",
                "ssm:Describe*",
                "ssm:Get*",
                "ssm:List*",
                "waf:Get*",
                "waf:List*",
                "waf-regional:Get*",
                "waf-regional:List*"
            ],
            "Resource": "*"
        }
    ]
}
```

**Or use AWS managed policy**: `SecurityAudit` (if available in your account)

## Creating IAM User and Access Keys

### Step 1: Create IAM User

1. Go to AWS Console → IAM → Users
2. Click "Create user"
3. Enter username (e.g., `cs-kit-setup-user` or `cs-kit-scan-user`)
4. Click "Next"

### Step 2: Attach Policies

1. Select "Attach policies directly"
2. Choose the appropriate policy:
   - For setup: `AmazonEC2FullAccess` (or custom policy above)
   - For scanning: `SecurityAudit` or custom read-only policy above
3. Click "Next" → "Create user"

### Step 3: Create Access Keys

1. Click on the created user
2. Go to "Security credentials" tab
3. Click "Create access key"
4. Choose "Command Line Interface (CLI)" or "Application running outside AWS"
5. Click "Next" → "Create access key"
6. **IMPORTANT**: Copy both:
   - Access Key ID
   - Secret Access Key
   - Store them securely (you won't be able to see the secret key again)

### Step 4: Configure Credentials

You can provide credentials in several ways:

**Option A: Environment Variables**
```bash
export AWS_ACCESS_KEY_ID=your_access_key_id
export AWS_SECRET_ACCESS_KEY=your_secret_access_key
export AWS_DEFAULT_REGION=us-east-1
```

**Option B: AWS Credentials File**
```bash
aws configure
# Enter Access Key ID
# Enter Secret Access Key
# Enter Default region: us-east-1
# Enter Default output format: json
```

**Option C: Pass to Scripts**
The setup scripts will automatically use environment variables or AWS credentials file.

## Running the Setup Script

### Step 1: Install Dependencies

```bash
# Install boto3 if not already installed
pip install boto3

# Or if using poetry
poetry add boto3
```

### Step 2: Run Setup Script

```bash
# Basic usage (creates 2 instances in us-east-1)
python scripts/setup_aws_dev_env.py

# Custom region and instance count
python scripts/setup_aws_dev_env.py --region us-west-2 --instance-count 3
```

The script will:
1. Create a VPC with public and private subnets
2. Create an Internet Gateway
3. Set up route tables
4. Create security groups (web app and general EC2)
5. Launch EC2 instances with a simple web application
6. Display a summary with public IPs

### Step 3: Verify Setup

1. Wait 2-3 minutes for instances to initialize
2. Visit the web app URL shown in the summary (e.g., `http://<public-ip>`)
3. You should see a simple HTML page with instance metadata

## Running CS-Kit Scan

Once your environment is set up, run CS-Kit:

```bash
# Using poetry
poetry run cs-kit run --provider aws --frameworks cis_aws_1_4 --regions us-east-1

# Or using Docker
docker run --rm \
  -v $(pwd)/artifacts:/app/artifacts \
  -v $(pwd)/reports:/app/reports \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  cs-kit:latest run --provider aws --frameworks cis_aws_1_4 --regions us-east-1
```

**Note**: Make sure to use the scan user credentials (read-only) for running scans, not the setup user credentials.

## Cleanup

To remove all created resources:

```bash
# Interactive cleanup (will prompt for confirmation)
python scripts/cleanup_aws_dev_env.py --region us-east-1

# Automatic cleanup (no prompt)
python scripts/cleanup_aws_dev_env.py --region us-east-1 --yes
```

## Troubleshooting

### "Access Denied" Errors

- Verify your IAM user has the correct permissions
- Check that access keys are correctly configured
- Ensure you're using the right credentials (setup vs scan user)

### "No AMI Found" Errors

- The script looks for Amazon Linux 2023 or Amazon Linux 2
- If these aren't available in your region, modify the script to use a different AMI

### Instances Not Accessible

- Wait 2-3 minutes after creation for initialization
- Check security group rules allow HTTP (port 80)
- Verify instances are in public subnet with public IPs

### Resources Not Found During Cleanup

- Resources are identified by tags (`Purpose: cs-kit-development`)
- If tags were modified, cleanup script won't find them
- Manually delete resources through AWS Console if needed

## Cost Considerations

The setup creates:
- 2x t3.micro EC2 instances (~$0.0104/hour each = ~$0.02/hour total)
- 1x VPC (free)
- 1x Internet Gateway (free)
- 2x Subnets (free)
- 2x Security Groups (free)
- Data transfer charges may apply

**Estimated cost**: ~$15/month if running 24/7

**Remember to clean up resources when not in use!**

## Security Notes

⚠️ **Important Security Considerations**:

1. **Development Only**: This setup is for development/testing only
2. **Public Access**: Security groups allow SSH and HTTP from anywhere (0.0.0.0/0)
3. **No HTTPS**: The web app runs on HTTP only
4. **Default Credentials**: Instances use default AMI credentials
5. **No Monitoring**: No CloudWatch alarms or logging configured

For production environments, implement:
- Restrictive security groups
- HTTPS/TLS certificates
- IAM roles for instances
- CloudWatch monitoring
- VPC Flow Logs
- Proper key management

## Next Steps

After setup:
1. Verify web app is accessible
2. Run CS-Kit scan to test security scanning
3. Review scan results and PDF reports
4. Experiment with different compliance frameworks
5. Clean up resources when done

For more information, see the main [README.md](README.md).

