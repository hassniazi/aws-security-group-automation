'''
Version 0.3
Copyright (c) IBM 2018
'''

import boto3
import csv
import logging
import os
import re
import sys
import yaml

import pprint

LOG_FILE        = '/tmp/securitygroupsegress.log'
DEFAULT_REGION  = 'eu-west-2'
DEFAULT_PROFILE = 'scotgov'
TEMPLATE_NAME   = 'GeneratedSecurityGroupsEgress{}.template.yaml'
RULE_COL        = 0
SG_TO_EDIT_COL  = 1
FROM_PORT_COL   = 2
TO_PORT_COL     = 3
PROTOCOL_COL    = 4
SG_TO_COL     = 5
FROM_TYPE_COL   = 6

def process_args():
    '''
    Args as follows:
    1. file_name     - the name of the input csv to read
    2. env_name      - the vpc suffix - e.g for the vpc mgmt-nonprod,
                       the env_name would be nonprod
    3. awsprofile    - the boto profile to be used, typically stored in
                       ~/.aws/credentials
    4. template_path - the output path into which AWS cloudformation 
                       templates should be placed.
    '''
    if len(sys.argv)-1 == 4:
        file_name = sys.argv[1]
        env_name = sys.argv[2]
        awsprofile = sys.argv[3]
        template_path = sys.argv[4]

        return (file_name, env_name, awsprofile, template_path)
    else:
        logging.info("Usage: python generate_egress_security_groups_v1.py 'CSVCPath/SGEsgress.csv' 'VPCSuffix' 'AWSAccountProfile' 'CSVCPath'")
        exit(1)

def main():
    if not os.path.exists(LOG_FILE):
        log_file = open(LOG_FILE, 'w+')
        log_file.close()
    logging.basicConfig(
        format='%(levelname)s: %(asctime)s %(message)s',
        datefmt='%d/%m/%Y %I:%M:%S %p',
        filename=LOG_FILE,
        level=logging.INFO
    )
    file_name, environment_name, awsprofile, template_path = process_args()
    csv_file_reader = CsvFileReader(file_name)
    csv_data = csv_file_reader.read_file()
    sg_generator = SecurityGroupGenerator(csv_data, aws_profile=awsprofile,
                                          env_name=environment_name)
    sg_generator.generate_security_group_structure()
    logging.info("Finished generating SG structure")
    sg_generator.write_to_file(template_path=template_path)

class CsvFileReader(object):
    '''
    Read a CSV file and return a 2D list of strings. Each sub-list
    represents a row in the input.
    '''
    def __init__(self, __filename):
        self.filename = __filename

    def read_file(self):
        with open(self.filename, 'rb') as csvfile:
            data = [row for row in csv.reader(csvfile.read().splitlines())]
            if len(data) == 0:
                raise ValueError('File {} appears to be empty'.format(self.filename))
            return data

class SecurityGroupGenerator(object):

    def __init__(self, __data, region=None, aws_profile=None, env_name=''):
        self.data = __data
        self.client = self.setup_boto_client(aws_profile, region)
        self.env_name = env_name
        self.groups = self.get_all_security_groups()
        self.container = {}
        self.vpc_ids = self.get_vpc_ids()
        self.network_inferfaces = self.get_network_interfaces()
        self.dc_group = self.get_domain_controller_group_id()
        self.nlb_cidrs = self.get_nlb_cidrs()
        logging.info('NLB CIDRS found: \n{}'.format(self.nlb_cidrs))

    def setup_boto_client(self, aws_profile, region, service='ec2'):
        '''
        Prepare boto3 client for interacting with AWS API
        '''
        if region is None: region = DEFAULT_REGION
        if aws_profile is None: aws_profile = DEFAULT_PROFILE
        session = boto3.Session(profile_name=aws_profile)
        return session.client(service, region_name=region)

    def query_filter(self, filter_key, *values):
        '''
        Prepare a query filter to be passed to an aws api lookup
        Note that values is a tuple or any additional arguments passed
        after the filter_key, allowing for multiple entries to be passed
        in as the 'Values' list
        '''
        return {'Filters': [{'Name': filter_key, 'Values': list(values)}]}

    def get_vpc_names(self):
        '''
        Return a list of VPC names
        '''
        return [
            s.format(self.env_name) for s in ['mgmt-{}', 'dmz-{}', 'appdata-{}']
        ]

    def get_vpc_ids(self):
        '''
        Use the boto client to lookup vpc ids associated with the environment
        '''
        vpcs = self.client.describe_vpcs(
            **self.query_filter('tag:Name', *self.get_vpc_names())
        ).get('Vpcs', [])
        return [vpc['VpcId'] for vpc in vpcs]

    def get_all_security_groups(self):
        '''
        Use the boto client to lookup all groups
        '''
        return self.client.describe_security_groups(
            **self.query_filter('vpc-id', *self.get_vpc_ids())
        ).get('SecurityGroups', [])
    
    def get_network_interfaces(self):
        '''
        Returns a list of network interfaces associated with the environment
        '''
        return self.client.describe_network_interfaces(
            **self.query_filter('vpc-id', *self.vpc_ids)
        ).get('NetworkInterfaces', [])

    def get_nlb_cidrs(self):
        '''
        Returns a dict of load balancer names and private ip addresses
        '''
        cidrs = {}
        for ni in self.network_inferfaces:
            if ni['InterfaceType'] == 'network_load_balancer':
                name = ni['Description'].split('/')[1]
                az = ni['AvailabilityZone']
                private_ip = ni['PrivateIpAddress']
                logging.info('Network interface for load balancer {} found in {} with ip {}'.format(
                    name, az, private_ip
                ))
                nlb = cidrs.setdefault(name, {})
                nlb[az] = private_ip + '/32'
        return cidrs
        

    def get_domain_controller_group_id(self):
        '''
        Gets the domain controller group id
        '''
        for ni in self.network_inferfaces:
            if 'directory' in ni['Description']:
                return ni['Groups'][0]['GroupId']

    def get_security_group_id(self, short_name):
        '''
        Looks up a security group based on the name
        '''
        if short_name.lower() == 'activedirectory' and self.dc_group:
            return self.dc_group
        for group in self.groups:
            logical_name = group.get('GroupName', '').lower()
            if "temp" in short_name.lower() and short_name.lower() in logical_name.lower():
                group_id = group.get('GroupId', '')
                return group_id
            elif short_name.lower() + "." in logical_name.lower() + ".":
                group_id = group.get('GroupId', '')
                return group_id

    def generate_security_group_structure(self):
        '''
        Generates a dictionary structure suitable for transforming into
        cloudformation templates.
        '''
        header_row_length = len(self.data[0])
        skipped_rules = []
        source_short_code_counters = {}

        for i in range(1, len(self.data)): # skip header
            row = self.data[i]
            if len(row) != header_row_length:
                logging.warning('Row {} has invalid length'.format(row))
            rule_id = format(int(row[RULE_COL]), '03')
            source_short_code = self.generate_short_code(row[SG_TO_EDIT_COL])
            if source_short_code_counters.get(source_short_code, "") == '':
                source_short_code_counters[source_short_code] = 1
            else:
                source_short_code_counters[source_short_code] = source_short_code_counters.get(source_short_code, "") + 1

            if row[FROM_TYPE_COL] == 'Group':
                destination_group_name = self.generate_group_name(row[SG_TO_COL])
                destination_group_id = self.get_security_group_id(destination_group_name)
                destination_cidr = None
            elif 'LB' in row[FROM_TYPE_COL]:
                destination = row[SG_TO_COL]
                vpc_prefix = destination.split('-')[0]
                lb_suffix = destination.split(vpc_prefix)[1]
                destination_lb = vpc_prefix + '-' + self.env_name + lb_suffix
                az = '{region}{az}'.format(
                    region=DEFAULT_REGION,
                    az=row[FROM_TYPE_COL].split('_')[1].lower()
                )
                destination_cidr = self.nlb_cidrs[destination_lb][az]
                destination_group_id = None
            elif row[FROM_TYPE_COL] == 'CIDR':
                destination_cidr = row[SG_TO_COL]
                destination_group_id = None
            source_group_name = self.generate_group_name(row[SG_TO_EDIT_COL])
            #logging.info('Rule {rule} rule for group {group} has short code {short_code}'.format(
            #    rule=rule_id,
            #    group=source_group_name,
            #    short_code=source_short_code
            #))
            source_group_id = self.get_security_group_id(source_group_name)
            resource_name = 'r' + source_group_name + 'Rule' + rule_id
            from_port = str(row[FROM_PORT_COL])
            to_port = str(row[TO_PORT_COL])
            protocol = str(row[PROTOCOL_COL].lower())
            if protocol == 'icmp' or from_port.lower() == 'all':
                from_port = '-1'
                to_port = '-1'
            if to_port == '0':
                to_port = from_port
            if '-' in from_port and '-' in to_port:
                split_ports = from_port.split('-')
                if len(split_ports) == 2:
                    from_port = split_ports[0]
                    to_port = split_ports[1]
            if from_port == '' and to_port == '':
                logging.warning('Invalid ports for group. Skipping rule number {}: {}'.format(rule_id, row))
                skipped_rules.append(rule_id)
                continue
            if source_group_id is None and destination_group_id is None:
                logging.warning('Source and Destination groups not found. Skipping rule number {}:\nUnable to find destination group {} and source group {}'.format(rule_id, destination_group_name, source_group_name))
                skipped_rules.append(rule_id)
                continue
            elif source_group_id is None:
                logging.warning('Primary group not found. Skipping rule number {}:\nUnable to find source group {}'.format(rule_id, source_group_name))
                skipped_rules.append(rule_id)
                continue
            elif destination_group_id is None and destination_cidr is None:
                logging.warning('Inbound group/CIDR not found. Skipping rule number {}:\nUnable to find destination group {}'.format(rule_id, destination_group_name))
                skipped_rules.append(rule_id)
                continue
            if row[FROM_TYPE_COL] == 'Group':
                egress_rule = {
                    'Type': 'AWS::EC2::SecurityGroupEgress',
                    'Properties': {
                        'GroupId': source_group_id,
                        'DestinationSecurityGroupId': destination_group_id,
                        'Description': 'Rule ID {}'.format(rule_id),
                        'IpProtocol': protocol,
                        'FromPort': from_port,
                        'ToPort': to_port,
                    }
                }
            else:
                egress_rule = {
                    'Type': 'AWS::EC2::SecurityGroupEgress',
                    'Properties': {
                        'GroupId': source_group_id,
                        'CidrIp': destination_cidr,
                        'Description': 'Rule ID {}'.format(rule_id),
                        'IpProtocol': protocol,
                        'FromPort': from_port,
                        'ToPort': to_port,
                    }
                }
            if (len(yaml.dump(self.container.get(source_short_code, {}))) >= 50000 
                or source_short_code_counters.get(source_short_code, 0) >= 200):
                source_short_code = source_short_code + "-extra"
                if source_short_code_counters.get(source_short_code, "") == '':
                    source_short_code_counters[source_short_code] = 1
                else:
                    source_short_code_counters[source_short_code] = source_short_code_counters.get(source_short_code, "") + 1
            #logging.info('Printing ITERITEMS {}'.format(len(yaml.dump(self.container.get(source_short_code, {})))))
            #logging.info('Printing ITERCODE COUNT {}'.format(source_short_code_counters.get(source_short_code, "")))
            self.safely_add_dict(egress_rule, key1=source_short_code, key2='Resources', key3=resource_name)
        if len(skipped_rules) > 0:
            logging.warning('Rows skipped: {}'.format(skipped_rules))
        else:
            logging.info('All rules processed succesffully.')
        logging.info('Rules processed: \n{}'.format(pprint.pformat(source_short_code_counters)))

    def write_to_file(self, template_path):
        '''
        Writes each element in self.container to file
        '''
        for short_name, template_data in self.container.iteritems():
            template_data['Description'] = 'Security Group Egress definitions'
            template_data['AWSTemplateFormatVersion'] = '2010-09-09'
            template_name = template_path + '/' + TEMPLATE_NAME.format(short_name.title())
            yaml_string = yaml.dump(template_data)
            with open(template_name, 'w+') as template_file:
                logging.info('Saving {} to disk.'.format(template_name))
                template_file.write(yaml_string)

    def generate_group_name(self, raw_name):
        '''
        Prepares a logical group name removing whitespace and
        putting into title case
        '''
        if 'temp' in raw_name.lower():
            return raw_name
        elif 'SSM' in raw_name:
            return raw_name
        clean_name = raw_name.lower().title()
        clean_name = re.sub(r"[^a-zA-Z0-9]", '', clean_name)
        return clean_name

    def generate_short_code(self, raw_name):
        '''
        Returns the first part of the group name from the raw input
        '''
        split_name = raw_name.split('_')[0].split(' ')
        return split_name[0].lower()

    # self.safely_add_dict(egress_rule, key1=source_short_code, key2='Resources', key3=resource_name)
    def safely_add_dict(self, d, key1=None, key2=None, key3=None):
        '''
        Safely adds a dictionary element to self.container
        '''
        d1 = self.container.get(key1, {})
        if d1 is not None and key2 not in d1:
            d1[key2] = {}
        if d1 is not None and key2 in d1:
            d2 = d1.get(key2)
            d2[key3] = d
            d1[key2] = d2
            self.container[key1] = d1

if __name__ == '__main__':
    main()
