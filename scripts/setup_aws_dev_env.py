#!/usr/bin/env python3
"""Setup AWS development environment for cs-kit testing.

This script creates:
- VPC with public and private subnets
- Internet Gateway and Route Tables
- Security Groups (web app and general EC2)
- EC2 instances with a simple web application
- Tags all resources for easy identification and cleanup

Usage:
    python scripts/setup_aws_dev_env.py --region us-east-1
"""

import argparse
import sys

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("ERROR: boto3 is required. Install it with: pip install boto3")
    sys.exit(1)


class AWSDevEnvironmentSetup:
    """Setup AWS development environment for security scanning."""

    def __init__(self, region: str = "us-east-1"):
        """Initialize AWS clients.

        Args:
            region: AWS region to create resources in
        """
        self.region = region
        self.ec2 = boto3.client("ec2", region_name=region)
        self.vpc_id: str | None = None
        self.public_subnet_id: str | None = None
        self.private_subnet_id: str | None = None
        self.igw_id: str | None = None
        self.web_sg_id: str | None = None
        self.ec2_sg_id: str | None = None
        self.instance_ids: list[str] = []

    def create_vpc(self) -> str:
        """Create a VPC with CIDR 10.0.0.0/16.

        Returns:
            VPC ID
        """
        print("Creating VPC...")
        try:
            response = self.ec2.create_vpc(
                CidrBlock="10.0.0.0/16",
                TagSpecifications=[
                    {
                        "ResourceType": "vpc",
                        "Tags": [
                            {"Key": "Name", "Value": "cs-kit-dev-vpc"},
                            {"Key": "Purpose", "Value": "cs-kit-development"},
                            {"Key": "ManagedBy", "Value": "cs-kit-setup-script"},
                        ],
                    }
                ],
            )
            self.vpc_id = response["Vpc"]["VpcId"]
            print(f"✓ Created VPC: {self.vpc_id}")

            # Enable DNS hostnames
            self.ec2.modify_vpc_attribute(
                VpcId=self.vpc_id, EnableDnsHostnames={"Value": True}
            )
            self.ec2.modify_vpc_attribute(
                VpcId=self.vpc_id, EnableDnsSupport={"Value": True}
            )

            return self.vpc_id
        except ClientError as e:
            print(f"ERROR: Failed to create VPC: {e}")
            raise

    def create_subnets(self) -> tuple[str, str]:
        """Create public and private subnets.

        Returns:
            Tuple of (public_subnet_id, private_subnet_id)
        """
        if not self.vpc_id:
            raise ValueError("VPC must be created first")

        print("Creating subnets...")
        try:
            # Get availability zones
            azs = self.ec2.describe_availability_zones()
            az_names = [az["ZoneName"] for az in azs["AvailabilityZones"][:2]]

            # Public subnet
            public_response = self.ec2.create_subnet(
                VpcId=self.vpc_id,
                CidrBlock="10.0.1.0/24",
                AvailabilityZone=az_names[0],
                TagSpecifications=[
                    {
                        "ResourceType": "subnet",
                        "Tags": [
                            {"Key": "Name", "Value": "cs-kit-dev-public-subnet"},
                            {"Key": "Purpose", "Value": "cs-kit-development"},
                        ],
                    }
                ],
            )
            self.public_subnet_id = public_response["Subnet"]["SubnetId"]
            print(f"✓ Created public subnet: {self.public_subnet_id}")

            # Private subnet
            private_response = self.ec2.create_subnet(
                VpcId=self.vpc_id,
                CidrBlock="10.0.2.0/24",
                AvailabilityZone=az_names[1],
                TagSpecifications=[
                    {
                        "ResourceType": "subnet",
                        "Tags": [
                            {"Key": "Name", "Value": "cs-kit-dev-private-subnet"},
                            {"Key": "Purpose", "Value": "cs-kit-development"},
                        ],
                    }
                ],
            )
            self.private_subnet_id = private_response["Subnet"]["SubnetId"]
            print(f"✓ Created private subnet: {self.private_subnet_id}")

            return self.public_subnet_id, self.private_subnet_id
        except ClientError as e:
            print(f"ERROR: Failed to create subnets: {e}")
            raise

    def create_internet_gateway(self) -> str:
        """Create and attach Internet Gateway.

        Returns:
            Internet Gateway ID
        """
        if not self.vpc_id:
            raise ValueError("VPC must be created first")

        print("Creating Internet Gateway...")
        try:
            # Create IGW
            igw_response = self.ec2.create_internet_gateway(
                TagSpecifications=[
                    {
                        "ResourceType": "internet-gateway",
                        "Tags": [
                            {"Key": "Name", "Value": "cs-kit-dev-igw"},
                            {"Key": "Purpose", "Value": "cs-kit-development"},
                        ],
                    }
                ]
            )
            self.igw_id = igw_response["InternetGateway"]["InternetGatewayId"]
            print(f"✓ Created Internet Gateway: {self.igw_id}")

            # Attach to VPC
            self.ec2.attach_internet_gateway(
                InternetGatewayId=self.igw_id, VpcId=self.vpc_id
            )
            print("✓ Attached IGW to VPC")

            return self.igw_id
        except ClientError as e:
            print(f"ERROR: Failed to create Internet Gateway: {e}")
            raise

    def create_route_tables(self) -> None:
        """Create route tables for public and private subnets."""
        if not self.vpc_id or not self.igw_id or not self.public_subnet_id:
            raise ValueError("VPC, IGW, and subnets must be created first")

        print("Creating route tables...")
        try:
            # Public route table
            public_rt_response = self.ec2.create_route_table(
                VpcId=self.vpc_id,
                TagSpecifications=[
                    {
                        "ResourceType": "route-table",
                        "Tags": [
                            {"Key": "Name", "Value": "cs-kit-dev-public-rt"},
                            {"Key": "Purpose", "Value": "cs-kit-development"},
                        ],
                    }
                ],
            )
            public_rt_id = public_rt_response["RouteTable"]["RouteTableId"]

            # Add route to internet gateway
            self.ec2.create_route(
                RouteTableId=public_rt_id,
                DestinationCidrBlock="0.0.0.0/0",
                GatewayId=self.igw_id,
            )

            # Associate with public subnet
            self.ec2.associate_route_table(
                RouteTableId=public_rt_id, SubnetId=self.public_subnet_id
            )
            print(f"✓ Created and configured public route table: {public_rt_id}")

            # Private route table (no internet gateway)
            private_rt_response = self.ec2.create_route_table(
                VpcId=self.vpc_id,
                TagSpecifications=[
                    {
                        "ResourceType": "route-table",
                        "Tags": [
                            {"Key": "Name", "Value": "cs-kit-dev-private-rt"},
                            {"Key": "Purpose", "Value": "cs-kit-development"},
                        ],
                    }
                ],
            )
            private_rt_id = private_rt_response["RouteTable"]["RouteTableId"]

            # Associate with private subnet
            self.ec2.associate_route_table(
                RouteTableId=private_rt_id, SubnetId=self.private_subnet_id
            )
            print(f"✓ Created and configured private route table: {private_rt_id}")

        except ClientError as e:
            print(f"ERROR: Failed to create route tables: {e}")
            raise

    def create_security_groups(self) -> tuple[str, str]:
        """Create security groups for web app and EC2 instances.

        Returns:
            Tuple of (web_sg_id, ec2_sg_id)
        """
        if not self.vpc_id:
            raise ValueError("VPC must be created first")

        print("Creating security groups...")
        try:
            # Web application security group
            web_sg_response = self.ec2.create_security_group(
                GroupName="cs-kit-dev-web-sg",
                Description="Security group for web application",
                VpcId=self.vpc_id,
                TagSpecifications=[
                    {
                        "ResourceType": "security-group",
                        "Tags": [
                            {"Key": "Name", "Value": "cs-kit-dev-web-sg"},
                            {"Key": "Purpose", "Value": "cs-kit-development"},
                        ],
                    }
                ],
            )
            self.web_sg_id = web_sg_response["GroupId"]

            # Allow HTTP, HTTPS, and SSH
            self.ec2.authorize_security_group_ingress(
                GroupId=self.web_sg_id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 80,
                        "ToPort": 80,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTP"}],
                    },
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTPS"}],
                    },
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "SSH"}],
                    },
                ],
            )
            print(f"✓ Created web security group: {self.web_sg_id}")

            # General EC2 security group (more restrictive)
            ec2_sg_response = self.ec2.create_security_group(
                GroupName="cs-kit-dev-ec2-sg",
                Description="Security group for general EC2 instances",
                VpcId=self.vpc_id,
                TagSpecifications=[
                    {
                        "ResourceType": "security-group",
                        "Tags": [
                            {"Key": "Name", "Value": "cs-kit-dev-ec2-sg"},
                            {"Key": "Purpose", "Value": "cs-kit-development"},
                        ],
                    }
                ],
            )
            self.ec2_sg_id = ec2_sg_response["GroupId"]

            # Allow SSH only
            self.ec2.authorize_security_group_ingress(
                GroupId=self.ec2_sg_id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "SSH"}],
                    }
                ],
            )
            print(f"✓ Created EC2 security group: {self.ec2_sg_id}")

            return self.web_sg_id, self.ec2_sg_id
        except ClientError as e:
            print(f"ERROR: Failed to create security groups: {e}")
            raise

    def get_latest_amazon_linux_ami(self) -> str:
        """Get the latest Amazon Linux 2023 AMI ID.

        Returns:
            AMI ID
        """
        # Well-known Amazon Linux 2 AMI IDs by region (updated periodically)
        # These are commonly available public AMIs
        known_amis = {
            "us-east-1": "ami-0c55b159cbfafe1f0",  # Amazon Linux 2, may need update
            "us-west-2": "ami-0d70546e43a941d70",
            "eu-west-1": "ami-0c94864ba95b798c7",
        }

        try:
            # Try using SSM Parameter Store (most reliable method) if permissions allow
            try:
                import boto3
                ssm = boto3.client("ssm", region_name=self.region)
                try:
                    # Try Amazon Linux 2023 first
                    response = ssm.get_parameter(
                        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64"
                    )
                    ami_id = response["Parameter"]["Value"]
                    print(f"✓ Found Amazon Linux 2023 AMI via SSM: {ami_id}")
                    return ami_id
                except ClientError:
                    # Fallback to Amazon Linux 2
                    try:
                        response = ssm.get_parameter(
                            Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
                        )
                        ami_id = response["Parameter"]["Value"]
                        print(f"✓ Found Amazon Linux 2 AMI via SSM: {ami_id}")
                        return ami_id
                    except ClientError:
                        pass
            except Exception:
                pass  # SSM not available, continue to other methods

            # Try to find AMI by searching
            try:
                response = self.ec2.describe_images(
                    Owners=["amazon"],
                    Filters=[
                        {"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]},
                        {"Name": "state", "Values": ["available"]},
                    ],
                    MaxResults=10,
                )
                if response["Images"]:
                    # Sort by creation date, get latest
                    images = sorted(
                        response["Images"], key=lambda x: x["CreationDate"], reverse=True
                    )
                    ami_id = images[0]["ImageId"]
                    print(f"✓ Found Amazon Linux 2 AMI: {ami_id}")
                    return ami_id
            except ClientError:
                pass

            # Fallback to known AMI for the region
            if self.region in known_amis:
                ami_id = known_amis[self.region]
                # Verify it exists
                try:
                    self.ec2.describe_images(ImageIds=[ami_id])
                    print(f"✓ Using known Amazon Linux 2 AMI for {self.region}: {ami_id}")
                    return ami_id
                except ClientError:
                    print(f"⚠ Known AMI {ami_id} not available, trying to find any Amazon Linux AMI...")

            # Last resort: try to find any Amazon Linux AMI
            try:
                response = self.ec2.describe_images(
                    Owners=["amazon"],
                    Filters=[
                        {"Name": "name", "Values": ["*amazon*linux*"]},
                        {"Name": "state", "Values": ["available"]},
                        {"Name": "architecture", "Values": ["x86_64"]},
                    ],
                    MaxResults=10,
                )
                if response["Images"]:
                    images = sorted(
                        response["Images"], key=lambda x: x["CreationDate"], reverse=True
                    )
                    ami_id = images[0]["ImageId"]
                    print(f"✓ Found Amazon Linux AMI: {ami_id} ({images[0]['Name']})")
                    return ami_id
            except ClientError:
                pass

            raise ValueError(
                f"No Amazon Linux AMI found in region {self.region}. "
                "Please check your permissions or specify an AMI ID manually."
            )
        except Exception as e:
            print(f"ERROR: Failed to find AMI: {e}")
            raise

    def create_user_data_script(self) -> str:
        """Create user data script to install and run a simple web app.

        Returns:
            Base64-encoded user data script
        """
        user_data = """#!/bin/bash
# Install and start a simple web server
yum update -y
yum install -y httpd

# Create a simple HTML page
cat > /var/www/html/index.html <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>CS-Kit Development Web App</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .info { background: #e8f4f8; padding: 15px; border-radius: 4px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to CS-Kit Development Environment</h1>
        <div class="info">
            <p><strong>Purpose:</strong> This is a test web application for security scanning.</p>
            <p><strong>Instance ID:</strong> $(curl -s http://169.254.169.254/latest/meta-data/instance-id)</p>
            <p><strong>Region:</strong> $(curl -s http://169.254.169.254/latest/meta-data/placement/region)</p>
            <p><strong>Availability Zone:</strong> $(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)</p>
        </div>
        <p>This environment is managed by cs-kit setup script.</p>
    </div>
</body>
</html>
EOF

# Start and enable httpd
systemctl start httpd
systemctl enable httpd

# Log completion
echo "Web server setup completed at $(date)" >> /var/log/user-data.log
"""
        return user_data

    def create_ec2_instances(self, count: int = 2, ami_id: str | None = None) -> list[str]:
        """Create EC2 instances.

        Args:
            count: Number of instances to create (default: 2)
            ami_id: Optional AMI ID to use (if not provided, will try to find one)

        Returns:
            List of instance IDs
        """
        if not self.public_subnet_id or not self.web_sg_id or not self.ec2_sg_id:
            raise ValueError("Subnets and security groups must be created first")

        print(f"Creating {count} EC2 instances...")
        try:
            if not ami_id:
                ami_id = self.get_latest_amazon_linux_ami()
            else:
                # Verify the provided AMI exists
                try:
                    self.ec2.describe_images(ImageIds=[ami_id])
                    print(f"✓ Using provided AMI: {ami_id}")
                except ClientError as e:
                    raise ValueError(f"Provided AMI {ami_id} not found or not accessible: {e}") from e
            user_data = self.create_user_data_script()

            # Create instances
            instances_to_create = []
            for i in range(count):
                is_web_app = i == 0  # First instance is web app
                sg_id = self.web_sg_id if is_web_app else self.ec2_sg_id
                instance_name = (
                    "cs-kit-dev-web-app" if is_web_app else f"cs-kit-dev-ec2-{i}"
                )
                user_data_script = user_data if is_web_app else ""

                instance_config = {
                    "ImageId": ami_id,
                    "MinCount": 1,
                    "MaxCount": 1,
                    "InstanceType": "t3.micro",
                    "SubnetId": self.public_subnet_id,
                    "SecurityGroupIds": [sg_id],
                    "UserData": user_data_script,
                    "TagSpecifications": [
                        {
                            "ResourceType": "instance",
                            "Tags": [
                                {"Key": "Name", "Value": instance_name},
                                {"Key": "Purpose", "Value": "cs-kit-development"},
                                {"Key": "ManagedBy", "Value": "cs-kit-setup-script"},
                            ],
                        }
                    ],
                }
                instances_to_create.append(instance_config)

            # Launch instances
            for instance_config in instances_to_create:
                response = self.ec2.run_instances(**instance_config)
                instance_id = response["Instances"][0]["InstanceId"]
                self.instance_ids.append(instance_id)
                instance_name = [
                    tag["Value"]
                    for tag in response["Instances"][0].get("Tags", [])
                    if tag["Key"] == "Name"
                ][0]
                print(f"✓ Launched instance: {instance_id} ({instance_name})")

            # Wait for instances to be running
            print("Waiting for instances to be running...")
            waiter = self.ec2.get_waiter("instance_running")
            waiter.wait(InstanceIds=self.instance_ids)
            print("✓ All instances are running")

            return self.instance_ids
        except ClientError as e:
            print(f"ERROR: Failed to create EC2 instances: {e}")
            raise

    def get_instance_public_ips(self) -> dict[str, str]:
        """Get public IPs of created instances.

        Returns:
            Dictionary mapping instance ID to public IP
        """
        if not self.instance_ids:
            return {}

        try:
            response = self.ec2.describe_instances(InstanceIds=self.instance_ids)
            ips = {}
            for reservation in response["Reservations"]:
                for instance in reservation["Instances"]:
                    instance_id = instance["InstanceId"]
                    public_ip = instance.get("PublicIpAddress", "N/A")
                    ips[instance_id] = public_ip
            return ips
        except ClientError as e:
            print(f"WARNING: Failed to get instance IPs: {e}")
            return {}

    def print_summary(self) -> None:
        """Print summary of created resources."""
        print("\n" + "=" * 60)
        print("AWS Development Environment Setup Complete!")
        print("=" * 60)
        print(f"\nRegion: {self.region}")
        print("\nCreated Resources:")
        print(f"  VPC: {self.vpc_id}")
        print(f"  Public Subnet: {self.public_subnet_id}")
        print(f"  Private Subnet: {self.private_subnet_id}")
        print(f"  Internet Gateway: {self.igw_id}")
        print(f"  Web Security Group: {self.web_sg_id}")
        print(f"  EC2 Security Group: {self.ec2_sg_id}")
        print(f"  EC2 Instances: {len(self.instance_ids)}")

        ips = self.get_instance_public_ips()
        if ips:
            print("\nInstance Public IPs:")
            for instance_id, ip in ips.items():
                instance_name = [
                    tag["Value"]
                    for tag in self.ec2.describe_instances(InstanceIds=[instance_id])[
                        "Reservations"
                    ][0]["Instances"][0].get("Tags", [])
                    if tag["Key"] == "Name"
                ]
                name = instance_name[0] if instance_name else instance_id
                if ip != "N/A":
                    print(f"  {name}: http://{ip}")
                else:
                    print(f"  {name}: {ip}")

        print("\n" + "=" * 60)
        print("Next Steps:")
        print("=" * 60)
        print("1. Wait a few minutes for instances to fully initialize")
        print("2. Test web app: Visit the HTTP URL above")
        print("3. Run cs-kit scan:")
        print(
            f"   poetry run cs-kit run --provider aws --frameworks cis_aws_1_4 --regions {self.region}"
        )
        print("\nTo clean up resources, use:")
        print("  python scripts/cleanup_aws_dev_env.py --region", self.region)
        print("=" * 60)

    def setup(self, instance_count: int = 2, ami_id: str | None = None) -> None:
        """Run the complete setup process.

        Args:
            instance_count: Number of EC2 instances to create
            ami_id: Optional AMI ID to use
        """
        try:
            self.create_vpc()
            self.create_subnets()
            self.create_internet_gateway()
            self.create_route_tables()
            self.create_security_groups()
            self.create_ec2_instances(count=instance_count, ami_id=ami_id)
            self.print_summary()
        except Exception as e:
            print(f"\nERROR: Setup failed: {e}")
            print("\nYou may need to clean up partially created resources manually.")
            sys.exit(1)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Setup AWS development environment for cs-kit testing"
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region to create resources in (default: us-east-1)",
    )
    parser.add_argument(
        "--instance-count",
        type=int,
        default=2,
        help="Number of EC2 instances to create (default: 2)",
    )
    parser.add_argument(
        "--ami-id",
        type=str,
        default=None,
        help="AMI ID to use (if not provided, will try to find Amazon Linux AMI)",
    )

    args = parser.parse_args()

    print("AWS Development Environment Setup for CS-Kit")
    print("=" * 60)
    print(f"Region: {args.region}")
    print(f"Instances: {args.instance_count}")
    print("=" * 60)
    print()

    # Check AWS credentials
    try:
        sts = boto3.client("sts", region_name=args.region)
        identity = sts.get_caller_identity()
        print("✓ AWS credentials verified")
        print(f"  Account: {identity.get('Account')}")
        print(f"  User/Role: {identity.get('Arn')}")
        print()
    except ClientError as e:
        print(f"ERROR: Failed to verify AWS credentials: {e}")
        print("\nPlease configure AWS credentials:")
        print("  - Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables")
        print("  - Or configure AWS CLI: aws configure")
        print("  - Or use IAM role if running on EC2")
        sys.exit(1)

    setup = AWSDevEnvironmentSetup(region=args.region)
    setup.setup(instance_count=args.instance_count, ami_id=args.ami_id)


if __name__ == "__main__":
    main()

