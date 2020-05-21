'''
Version 0.3
'''

import boto3
import csv
import logging
import os
import re
import sys
import yaml

LOG_FILE = '/tmp/GenerateBasicSecurityGroups.log'
DEFAULT_REGION = 'eu-west-2'
DEFAULT_VPCSHORTCODE_TAG = 'VPC_Short_Code'
TEMPLATE_NAME = 'GeneratedSecurityGroups{}.template.yaml'
MAX_RESOURCES_PER_TEMPLATE = 60

def get_csv_file_name():
    if len(sys.argv) > 1:
        return sys.argv[1]
    else:
        logging.info('Unable to open CSV. No file name supplied by user.')

def get_profile():
        return sys.argv[2]
        
def get_vpc():
        return sys.argv[3]
        
def get_template_path():
        return sys.argv[4]

def main():
    if not os.path.exists(LOG_FILE):
        log_file = open(LOG_FILE, 'w+')
        log_file.close()
    logging.basicConfig(
        format='%(asctime)s %(message)s', 
        datefmt='%d/%m/%Y %I:%M:%S %p', 
        filename=LOG_FILE,
        level=logging.INFO
    )
    file_name = get_csv_file_name()
    awsprofile = get_profile()
    vpc_short_code_p2 = get_vpc().lower()
    vpc_tag = 'VPC_Short_Code'
    template_path = get_template_path()
    csv_file_reader = CsvFileReader(file_name)
    csv_data = csv_file_reader.read_file()
    csv_data = csv_file_reader.read_file()
    sg_generator = SecurityGroupGenerator(csv_data, aws_profile=awsprofile)
    sg_generator.generate_security_group_structure(vpc_short_code_part2=vpc_short_code_p2, vpc_tag=vpc_tag)
    sg_generator.generate_templates(template_path=template_path)

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
    
    def __init__(self, __data, region=None, aws_profile=None):
        self.data = __data
        self.client = self.setup_boto_client(aws_profile, region)
        self.vpcs = self.client.describe_vpcs().get('Vpcs', [])
        self.resources = []
        
    def setup_boto_client(self, aws_profile, region):
        '''
        Prepare boto3 client for interacting with AWS API
        '''
        if region is None: region = DEFAULT_REGION
        session = boto3.Session(profile_name=aws_profile)
        return session.client('ec2', region_name=region)
    
    def describe_vpcs(self):
        '''
        Gather data on all VPCs for debugging
        '''
        vpcs = self.client.describe_vpcs().get('Vpcs', [])
        for vpc in vpcs:
            logging.info(vpc.get('VpcId', ''))
        
    def get_vpc_short_code(self, vpc_id, vpc_tag):
        '''
        Lookup vpc short code based on vpc id, getting values
        from AWS
        '''
        vpc = self.client.describe_vpcs(
            Filters = [
                {
                    'Name': 'vpc-id',
                    'Values': [vpc_id]
                }
            ]
        ).get('Vpcs', [])[0]
        tags = {
            tag['Key']: tag['Value']
            for tag in vpc.get('Tags', [])
        }
        return tags.get(vpc_tag, '')
    
    def get_vpc_id(self, vpc_short_code, vpc_tag):
        '''
        Gets the VPC ID based on a vpc short code
        '''
        for vpc in self.vpcs:
            tags = {
                tag['Key']: tag['Value']
                for tag in vpc.get('Tags', [])
            }
            if tags.get(vpc_tag, '') == vpc_short_code:
                return vpc.get('VpcId', '')
        return ''
        
        
    
    def generate_security_group_structure(self, vpc_short_code_part2=None, vpc_tag=None):
        '''
        Creates a dictionary structure representing the components of
        an AWS CloudFormation template.
        '''
        resources = {}
        outputs = {}
        vpc_id = ''
        vpc_short_code = ''
        header_row_length = len(self.data[0])
        resources = []
        for i in range(1, len(self.data)): # skip header
            resource = {}
            row = self.data[i]
            if len(row) != header_row_length:
                logging.warning('Row {} has invalid length'.format(row))
            group_name = self.generate_group_name(row[0])
            vpc_short_code_part1 = str(row[2]).lower()
            vpc_short_code = '{}-{}'.format(vpc_short_code_part1, vpc_short_code_part2)
            vpc_id = self.get_vpc_id(vpc_short_code, vpc_tag)
            #if _vpc_id != vpc_id: # only do lookups for new values
            #    vpc_short_code = self.get_vpc_short_code(_vpc_id)
            #    vpc_id = _vpc_id
            resource_name = 'r' + group_name
            export_name = vpc_short_code + '-SecurityGroup-' + group_name
            resource['resource_name'] = resource_name
            resource['Resource'] = {
                'Type': 'AWS::EC2::SecurityGroup',
                'Properties': {
                    'GroupDescription': row[1],
                    'GroupName': export_name,
                    'VpcId': vpc_id,
                    'SecurityGroupIngress': [],
                    'SecurityGroupEgress': [],
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': export_name
                        },
                        {
                            'Key': vpc_tag,
                            'Value': vpc_short_code
                        }
                    ]
                }
            }
            output_name = 'o' + group_name
            resource['output_name'] = output_name
            resource['Output'] = {
                'Description': row[1],
                'Value': {'Ref': resource_name},
                'Export': {
                    'Name': export_name
                }
            }
            self.resources.append(resource)
    
    def generate_templates(self, template_path=None):
        '''
        Generate a series of cloudformation templates
        '''
        i = 0
        template_num = 1
        template = {
            'AWSTemplateFormatVersion': '2010-09-09',
            'Description': 'Security Group definitions',
        }
        template_resources = {}
        template_outputs = {}
        while i < len(self.resources):
            resource = self.resources[i]
            logging.info(resource)
            template_resources[resource.get('resource_name')] = resource.get('Resource')
            template_outputs[resource.get('resource_name')] = resource.get('Output')
            if (i > 0 and (i + 1) % MAX_RESOURCES_PER_TEMPLATE == 0) or i == len(self.resources) - 1:
                template['Resources'] = template_resources
                template['Outputs'] = template_outputs
                template_name = template_path + '/' + TEMPLATE_NAME
                self.write_to_file(template, template_num, template_name)
                template = {
                    'AWSTemplateFormatVersion': '2010-09-09',
                    'Description': 'Security Group definitions {}'.format(template_num),
                }
                template_resources = {}
                template_outputs = {}
                template_num += 1
            i += 1
        
    
    def write_to_file(self, template, n, template_name):
        '''
        Write the dictionary structure (self.template) to file
        '''
        yaml_string = yaml.dump(template)
        template_name = template_name.format(n)
        with open(template_name, 'w+') as template_file:
            template_file.write(yaml_string)
    
    def generate_group_name(self, raw_name):
        '''
        Prepares a logical group name removing whitespace and
        putting into title case
        '''
        clean_name = raw_name.lower().title()
        clean_name = re.sub(r"[^a-zA-Z0-9]", '', clean_name)
        return clean_name
        
    def generate_vpc_id(self, raw_vpc_id):
        '''
        A simple check on the format of the vpc id string
        '''
        vpc_id = ''
        if raw_vpc_id[:4] != 'vpc-':
            vpc_id = 'vpc-' + raw_vpc_id
        else:
            vpc_id = raw_vpc_id
        return vpc_id

if __name__ == '__main__':
    main()