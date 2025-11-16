#!/usr/bin/env python3
"""Cleanup AWS development environment created by setup_aws_dev_env.py.

This script removes all resources created by the setup script:
- EC2 instances
- Security Groups
- Route Tables
- Internet Gateway
- Subnets
- VPC

Usage:
    python scripts/cleanup_aws_dev_env.py --region us-east-1
"""

import argparse
import sys

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("ERROR: boto3 is required. Install it with: pip install boto3")
    sys.exit(1)


class AWSDevEnvironmentCleanup:
    """Cleanup AWS development environment."""

    def __init__(self, region: str = "us-east-1"):
        """Initialize AWS clients.

        Args:
            region: AWS region to clean up resources in
        """
        self.region = region
        self.ec2 = boto3.client("ec2", region_name=region)

    def find_resources_by_tags(self) -> dict[str, list[str]]:
        """Find all resources tagged with cs-kit-development.

        Returns:
            Dictionary with resource types as keys and lists of IDs as values
        """
        resources = {
            "instances": [],
            "security_groups": [],
            "subnets": [],
            "route_tables": [],
            "internet_gateways": [],
            "vpcs": [],
        }

        try:
            # Find VPCs
            vpcs = self.ec2.describe_vpcs(
                Filters=[
                    {"Name": "tag:Purpose", "Values": ["cs-kit-development"]},
                    {"Name": "tag:ManagedBy", "Values": ["cs-kit-setup-script"]},
                ]
            )
            resources["vpcs"] = [vpc["VpcId"] for vpc in vpcs["Vpcs"]]

            # Find instances
            instances = self.ec2.describe_instances(
                Filters=[
                    {"Name": "tag:Purpose", "Values": ["cs-kit-development"]},
                    {"Name": "tag:ManagedBy", "Values": ["cs-kit-setup-script"]},
                    {"Name": "instance-state-name", "Values": ["running", "stopped"]},
                ]
            )
            resources["instances"] = [
                inst["InstanceId"]
                for res in instances["Reservations"]
                for inst in res["Instances"]
            ]

            # Find security groups
            sgs = self.ec2.describe_security_groups(
                Filters=[
                    {"Name": "tag:Purpose", "Values": ["cs-kit-development"]},
                ]
            )
            resources["security_groups"] = [sg["GroupId"] for sg in sgs["SecurityGroups"]]

            # Find subnets
            subnets = self.ec2.describe_subnets(
                Filters=[
                    {"Name": "tag:Purpose", "Values": ["cs-kit-development"]},
                ]
            )
            resources["subnets"] = [sn["SubnetId"] for sn in subnets["Subnets"]]

            # Find route tables
            rts = self.ec2.describe_route_tables(
                Filters=[
                    {"Name": "tag:Purpose", "Values": ["cs-kit-development"]},
                ]
            )
            resources["route_tables"] = [rt["RouteTableId"] for rt in rts["RouteTables"]]

            # Find internet gateways
            igws = self.ec2.describe_internet_gateways(
                Filters=[
                    {"Name": "tag:Purpose", "Values": ["cs-kit-development"]},
                ]
            )
            resources["internet_gateways"] = [
                igw["InternetGatewayId"] for igw in igws["InternetGateways"]
            ]

        except ClientError as e:
            print(f"ERROR: Failed to find resources: {e}")
            raise

        return resources

    def terminate_instances(self, instance_ids: list[str]) -> None:
        """Terminate EC2 instances.

        Args:
            instance_ids: List of instance IDs to terminate
        """
        if not instance_ids:
            return

        print(f"Terminating {len(instance_ids)} instances...")
        try:
            self.ec2.terminate_instances(InstanceIds=instance_ids)
            print(f"✓ Termination initiated for instances: {', '.join(instance_ids)}")

            # Wait for termination
            print("Waiting for instances to terminate...")
            waiter = self.ec2.get_waiter("instance_terminated")
            waiter.wait(InstanceIds=instance_ids)
            print("✓ All instances terminated")
        except ClientError as e:
            print(f"ERROR: Failed to terminate instances: {e}")
            raise

    def delete_security_groups(self, sg_ids: list[str], vpc_id: str) -> None:
        """Delete security groups.

        Args:
            sg_ids: List of security group IDs
            vpc_id: VPC ID (for filtering)
        """
        if not sg_ids:
            return

        print(f"Deleting {len(sg_ids)} security groups...")
        for sg_id in sg_ids:
            try:
                self.ec2.delete_security_group(GroupId=sg_id)
                print(f"✓ Deleted security group: {sg_id}")
            except ClientError as e:
                if "DependencyViolation" in str(e):
                    print(f"⚠ Security group {sg_id} still in use, skipping")
                else:
                    print(f"ERROR: Failed to delete security group {sg_id}: {e}")

    def detach_and_delete_igw(self, igw_ids: list[str], vpc_id: str) -> None:
        """Detach and delete internet gateways.

        Args:
            igw_ids: List of internet gateway IDs
            vpc_id: VPC ID to detach from
        """
        if not igw_ids:
            return

        print(f"Detaching and deleting {len(igw_ids)} internet gateways...")
        for igw_id in igw_ids:
            try:
                # Check attachments
                igw_info = self.ec2.describe_internet_gateways(
                    InternetGatewayIds=[igw_id]
                )
                attachments = igw_info["InternetGateways"][0].get("Attachments", [])

                # Detach from VPCs
                for attachment in attachments:
                    if attachment["VpcId"] == vpc_id:
                        self.ec2.detach_internet_gateway(
                            InternetGatewayId=igw_id, VpcId=vpc_id
                        )
                        print(f"✓ Detached IGW {igw_id} from VPC {vpc_id}")

                # Delete IGW
                self.ec2.delete_internet_gateway(InternetGatewayId=igw_id)
                print(f"✓ Deleted internet gateway: {igw_id}")
            except ClientError as e:
                print(f"ERROR: Failed to delete internet gateway {igw_id}: {e}")

    def delete_subnets(self, subnet_ids: list[str]) -> None:
        """Delete subnets.

        Args:
            subnet_ids: List of subnet IDs
        """
        if not subnet_ids:
            return

        print(f"Deleting {len(subnet_ids)} subnets...")
        for subnet_id in subnet_ids:
            try:
                self.ec2.delete_subnet(SubnetId=subnet_id)
                print(f"✓ Deleted subnet: {subnet_id}")
            except ClientError as e:
                print(f"ERROR: Failed to delete subnet {subnet_id}: {e}")

    def delete_route_tables(self, rt_ids: list[str], vpc_id: str) -> None:
        """Delete route tables (except main).

        Args:
            rt_ids: List of route table IDs
            vpc_id: VPC ID
        """
        if not rt_ids:
            return

        print(f"Deleting {len(rt_ids)} route tables...")
        for rt_id in rt_ids:
            try:
                # Check if it's the main route table
                rt_info = self.ec2.describe_route_tables(RouteTableIds=[rt_id])
                is_main = rt_info["RouteTables"][0].get("Associations", [{}])[
                    0
                ].get("Main", False)

                if is_main:
                    print(f"⚠ Skipping main route table: {rt_id}")
                    continue

                self.ec2.delete_route_table(RouteTableId=rt_id)
                print(f"✓ Deleted route table: {rt_id}")
            except ClientError as e:
                print(f"ERROR: Failed to delete route table {rt_id}: {e}")

    def delete_vpc(self, vpc_id: str) -> None:
        """Delete VPC.

        Args:
            vpc_id: VPC ID
        """
        if not vpc_id:
            return

        print(f"Deleting VPC: {vpc_id}...")
        try:
            self.ec2.delete_vpc(VpcId=vpc_id)
            print(f"✓ Deleted VPC: {vpc_id}")
        except ClientError as e:
            print(f"ERROR: Failed to delete VPC {vpc_id}: {e}")
            raise

    def cleanup(self, confirm: bool = False) -> None:
        """Run the complete cleanup process.

        Args:
            confirm: Skip confirmation prompt if True
        """
        print("Finding resources to clean up...")
        resources = self.find_resources_by_tags()

        # Count total resources
        total = sum(len(v) for v in resources.values())
        if total == 0:
            print("✓ No resources found to clean up")
            return

        print(f"\nFound {total} resources to clean up:")
        for resource_type, ids in resources.items():
            if ids:
                print(f"  {resource_type}: {len(ids)}")

        if not confirm:
            response = input("\nDo you want to proceed with cleanup? (yes/no): ")
            if response.lower() != "yes":
                print("Cleanup cancelled")
                return

        try:
            # Order matters for cleanup
            vpc_id = resources["vpcs"][0] if resources["vpcs"] else None

            # 1. Terminate instances first
            self.terminate_instances(resources["instances"])

            # 2. Delete security groups
            self.delete_security_groups(resources["security_groups"], vpc_id)

            # 3. Detach and delete internet gateways
            if vpc_id:
                self.detach_and_delete_igw(resources["internet_gateways"], vpc_id)

            # 4. Delete route tables
            if vpc_id:
                self.delete_route_tables(resources["route_tables"], vpc_id)

            # 5. Delete subnets
            self.delete_subnets(resources["subnets"])

            # 6. Delete VPC (last)
            if vpc_id:
                self.delete_vpc(vpc_id)

            print("\n" + "=" * 60)
            print("Cleanup Complete!")
            print("=" * 60)
        except Exception as e:
            print(f"\nERROR: Cleanup failed: {e}")
            print("Some resources may still exist. Please check manually.")
            sys.exit(1)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Cleanup AWS development environment created by setup script"
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region to clean up resources in (default: us-east-1)",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirmation prompt",
    )

    args = parser.parse_args()

    print("AWS Development Environment Cleanup for CS-Kit")
    print("=" * 60)
    print(f"Region: {args.region}")
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
        sys.exit(1)

    cleanup = AWSDevEnvironmentCleanup(region=args.region)
    cleanup.cleanup(confirm=args.yes)


if __name__ == "__main__":
    main()

