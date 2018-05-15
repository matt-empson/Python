# Lists security groups that aren't used/attached to EC2 Instances,
# Classic Load Balancers and Application Load Balancers.
# TODO Add checks for other services - EFS, RDS etc.
import boto3
import re

session = boto3.session.Session(profile_name=<insert aws credentials profile>,region_name=<insert region>)
classic_elb = session.client('elb')
ec2 = session.resource("ec2")
elb = session.client('elbv2')
sg = session.client("ec2")

classic_elbs = classic_elb.describe_load_balancers()
elbs = elb.describe_load_balancers()
instances = ec2.instances.all()
security_group = sg.describe_security_groups()

# Set a counter
unused_group_count = 0

# Get security groups attached to Classic and Application ELBs
classic_elb_security_groups = [classic_elb_security_group["SecurityGroups"] 
    for classic_elb_security_group in classic_elbs["LoadBalancerDescriptions"]]

elb_security_groups = [elb_security_group["SecurityGroups"] 
    for elb_security_group in elbs["LoadBalancers"]]

## classic_elb_security_groups and elb_security_groups returns nested list - flatten the lists
flattened_classic_elb_security_groups = sum(classic_elb_security_groups, [])
flattened_elb_security_groups = sum(elb_security_groups, [])

# Get security groups attached to instances
instance_security_groups = [security_group["GroupId"]
    for instance in instances
    for security_group in instance.security_groups]

# Get ALL security groups
security_groups = [group["GroupId"] 
    for group in security_group["SecurityGroups"]]

# Work out unused security groups
unused_security_groups = list(set(security_groups) - set(flattened_elb_security_groups) - set(flattened_classic_elb_security_groups) - set(instance_security_groups))
unused_security_groups.sort()

# REGEX to match AWS Directory Service security groups for exclusion from list
regex_aws_dc = re.compile(r"d-([0-9a-z]*)_controllers") 

# Print list of unused security groups
for unused_sg in unused_security_groups:
    unused_group = ec2.SecurityGroup(unused_sg)
    if unused_group.group_name != "default" and regex_aws_dc.search(unused_group.group_name) == None:
        print("\n======================================================================")
        print(f"Security Group Name: {unused_group.group_name}")
        print(f"Security Group ID: {unused_group.group_id}")
        print(f"Security Group Description: {unused_group.description}")
        print("======================================================================")
        unused_group_count += 1

print(f"\n\nTOTAL UNUSED GROUPS: {unused_group_count}")