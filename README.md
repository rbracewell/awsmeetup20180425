# awsmeetup20180425
* Using CloudFormation StackSets: enable AWS Config across all regions within an account
* Using AWS Config: deploy a custom rule that inspects S3 for encryption
* Using Lambda: record custom metrics to Cloudwatch

# WARNING
## _Running the below steps will incur AWS changes without your account_

## Pre-requisites
* Config and Cloudformation StackSets must not already be enabled

## Steps
* Launch the CloudFormation template stacksets/stacksets.yml - this will create the necessary roles for StackSets
* From StackSets launch the template config/config.yml - this will enable config
* Package the Python Lambda function configrule/encryption.py and deploy to S3
* Launch the CloudFormation template configrule/encryptionrule.yml - this will evaluate S3 buckets for encryption at rest
* Launch the CloudFormation template cloudwatch/customconfigmetric.yml - this will publish custom metrics to Cloudwatch regarding the non-compliant status of a rule
