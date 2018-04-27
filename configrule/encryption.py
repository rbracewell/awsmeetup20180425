import json
import boto3
import logging
from botocore.exceptions import ClientError

config = boto3.client('config')
s3 = boto3.client('s3')
log = logging.getLogger()
log.setLevel(logging.INFO)

class ConfigRule:
    def __init__(self, configurationItem):
        self.configurationItem = configurationItem
        self.relationships = configurationItem['relationships']

    def evaluate_compliance(self, configurationItem=None):
        return 'NOT_APPLICABLE'

    def get_relationship(self, relationships, id):
        for i in relationships:
            if i['resourceId'] == id:
                return i
        return None

    def find_relationships_by_type(self, type, relationships=None):
        if not relationships:
            relationships = self.relationships
        result = []
        for i in relationships:
            if i['resourceType'] == type:
                result.append(i)
        return result

    def get_related_configuration_item(self, relationship):
        result = config.get_resource_config_history(
            resourceType=relationship['resourceType'],
            resourceId=relationship['resourceId'],
            limit=1,
        )
        item = result['configurationItems'][0]
        if item.has_key('configuration'):
            item['configuration'] = json.loads(item['configuration'])
        return item

    def put_evaluations(self, compliance, annotation, resultToken):
        config.put_evaluations(
            Evaluations=[
                {
                    'ComplianceResourceType': self.configurationItem['resourceType'],
                    'ComplianceResourceId': self.configurationItem['resourceId'],
                    'ComplianceType': compliance,
                    'Annotation': annotation,
                    'OrderingTimestamp': self.configurationItem['configurationItemCaptureTime']
                },
            ],
            ResultToken=resultToken
        )


class RaiseEncryption(ConfigRule):
    def evaluate_compliance(self, configurationItem=None):
        if not configurationItem:
            configurationItem = self.configurationItem
        relationships = self.relationships
        if configurationItem['configurationItemStatus'] == 'ResourceDeleted':
            return ('NOT_APPLICABLE', "{} was deleted and therefore cannot be validated".format(configurationItem['resourceId']))
        if configurationItem['resourceType'] == 'AWS::S3::Bucket':
            try:
                response = s3.get_bucket_encryption(Bucket=configurationItem['resourceId'])
                if response['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] == "AES256":
                    return ('COMPLIANT', "[AWS::S3::Bucket] {} leverages Server Side Encryption with AES256".format(configurationItem['resourceId']))
                else:
                    return ('COMPLIANT', "[AWS::S3::Bucket] {} leverages Server Side Encryption with {} [{}]".format(configurationItem['resourceId'], response['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'], response['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['KMSMasterKeyID']))
            except ClientError:
                log.info("Processing S3 bucket supplimentary configuration [{}]".format(configurationItem["supplementaryConfiguration"]))
            bucket_policy = configurationItem["supplementaryConfiguration"].get(
                "BucketPolicy")
            if bucket_policy['policyText'] is None:
                return ('NON_COMPLIANT', "[AWS::S3::Bucket] {} is not encrypted".format(configurationItem['resourceId']))
            else:
                policy_text = json.loads(bucket_policy['policyText'])
                deny_statements = [
                    d for d in policy_text['Statement'] if d['Effect'] in ['Deny']]
                for statement in deny_statements:
                    try:
                        action = statement['Action']
                        condition = statement['Condition']
                        encryption = condition['StringNotEquals']
                        if action == "s3:PutObject" and "s3:x-amz-server-side-encryption" in encryption:
                            return ('COMPLIANT', "[AWS::S3::Bucket] {} uses a bucket policy to leverage Server Side Encryption with {}".format(configurationItem['resourceId'], encryption.get('s3:x-amz-server-side-encryption')))
                    except:
                        continue
                return ('NON_COMPLIANT', "[AWS::S3::Bucket] {} is not encrypted".format(configurationItem['resourceId']))
            return ('NON_COMPLIANT', "[AWS::S3::Bucket] {} Unexpected error occurred while querying encryption configuration".format(configurationItem['resourceId']))


def configrule(event, context):
    try:
        compliance = 'NON_COMPLIANT'
        annotation = 'An error occurred'
        invokingEvent = json.loads(event['invokingEvent'])
        configurationItem = invokingEvent['configurationItem']
    except:
        raise Exception('Could not load configuration item', event)
    try:
        rule = RaiseEncryption(configurationItem)
        compliance, annotation = rule.evaluate_compliance()
        log.info("Evaluation for resource [{}] Status: {} Annotation: {}".format(configurationItem['resourceId'], compliance, annotation))
    except:
        raise Exception('Could not process configuration item', configurationItem)
    rule.put_evaluations(compliance, annotation, event['resultToken'])