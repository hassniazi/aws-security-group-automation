# aws-security-group-automation
A number of python jobs to automate the creation and manipulation of AWS security groups
It takes an input of a csv file in the attached format and produces the neccessary cloudformation stack to generate the security groups and their rules.
# usage
1. Create security groups using the attached security group creation csv (you'll need to fill in Security Group Name,  Description and your VPC name reference)
2. Create Ingress rules (if using inter VPC or VPC peering this can be a security group name, if using Transit Gateway, the values will need to be CIDR ranges)
3. Create Egress rules (if using inter VPC or VPC peering this can be a security group name, if using Transit Gateway, the values will need to be CIDR ranges)
4. Fill in this CSV to map instance names (based on instance_role tag) to security groups.
