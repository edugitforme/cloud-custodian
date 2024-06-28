"""
Service Discovery Communications
"""
from c7n.manager import resources
from c7n.query import (
    ChildResourceManager,
    QueryResourceManager,
    TypeInfo,
    DescribeSource,
    ConfigSource,
)
from c7n.tags import universal_augment


class DescribeServiceDiscovery(DescribeSource):
    # override default describe augment to get tags
    def augment(self, resources):
        detailed_resources = super(DescribeServiceDiscovery, self).augment(resources)
        tagged_resources = universal_augment(self.manager, detailed_resources)
        return tagged_resources


@resources.register('servicediscovery')
class ServiceDiscovery(QueryResourceManager):
    source_mapping = {'describe': DescribeServiceDiscovery,
                      'config': ConfigSource}

    # interior class that defines the aws metadata for resource
    class resource_type(TypeInfo):
        service = 'servicediscovery'

        # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html  # noqa
        cfn_type = 'AWS::ServiceDiscovery::Service'

        # https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html  # noqa
        config_type = 'AWS::ServiceDiscovery::Service'

        # id: Needs to be the field that contains the id of the service as that's
        # what the service from servicediscovery API's expect.
        id = 'Id'

        # This name value appears in the "report" command output.
        # example: custodian  report --format json  -s report-out servicediscovery-policy.yml
        name = 'Name'

        # Turn on collection of the tags for this resource
        universal_taggable = object()

        # enum_spec (list_services) function has arn as a top level field
        arn = "Arn"

        enum_spec = ('list_services', 'Services', None)

        # get_service is the op to call
        # Id is the name of the parementer field in the detail call args to populate
        # Id is the key which is present in the enum response to map into the call arg
        # Service is the path in the response to pull out and merge into the list
        # response as the final product.
        detail_spec = ('get_service', 'Id', 'Id', 'Service')

        # refers to a field in the metadata response of the describe function
        # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/servicediscovery/client/get_service.html
        date = 'CreateDate'


@resources.register('servicediscovery-instance')
class ServiceDiscoveryInstance(ChildResourceManager):
    # interior class that defines the aws metadata for resource
    class resource_type(TypeInfo):

        supports_trailevents = True

        service = 'servicediscovery'

        # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html  # noqa
        cfn_type = 'AWS::ServiceDiscovery::Instance'

        # https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html  # noqa
        config_type = 'AWS::ServiceDiscovery::Instance'

        # turn on automatic collection of tags and tag filtering
        universal_taggable = object()

        # id: is not used by the resource collection process for this type because
        # this is a ChildResourceManager and instead it is the parent_spec function that drives
        # collection of "service id's".
        # However, it is still used by "report" operation so let's define it as something
        # even if not ideal.
        id = "Id"

        # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-instance.html # noqa
        arn = "Id"

        name = 'Id'

        # When we define a parent_spec then the parent_spec
        # provides the driving result set from which parent resource id's will be picked.
        # In this case the parent resource id is the ServiceId.
        # This is then iterated across and the enum_spec is called once for each parent 'id'.
        #
        # "servicediscovery" - identifies the parent data source (ie service discovery services).
        # "ServiceId" - is the field from the parent spec result that will be pulled out and
        # used to drive the service discovery instance enum_spec.
        parent_spec = ('servicediscovery', 'ServiceId', None)

        # enum_spec's list function is called once for each key (service id) returned from
        # the parent_spec.
        # 'Instances' - is path in the enum_spec response to locate the instances
        # for the given service id.
        # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/servicediscovery/client/list_instances.html # noqa
        enum_spec = (
            'list_instances',
            'Instances',
            None,
        )


class DescribeServiceDiscoveryNamespace(DescribeSource):
    # override default describe augment to get tags
    def augment(self, resources):
        detailed_resources = super(DescribeServiceDiscoveryNamespace, self).augment(resources)
        tagged_resources = universal_augment(self.manager, detailed_resources)
        return tagged_resources


@resources.register('servicediscovery-namespace')
class ServiceDiscoveryNamespace(QueryResourceManager):

    source_mapping = {'describe': DescribeServiceDiscoveryNamespace,
                      'config': ConfigSource}

    # interior class that defines the aws metadata for resource
    class resource_type(TypeInfo):
        service = 'servicediscovery'

        # id: Needs to be the field that contains the name of the service as that's
        # what the service discovery API's expect.
        id = 'Name'

        # This name value appears in the "report" command output.
        # example:
        # custodian  report --format json  -s report-out service-discovery-namespace-policy.yml
        name = 'Name'

        # Turn on collection of the tags for this resource
        universal_taggable = object()

        # enum_spec (list_namespaces) function has arn as a top level field
        arn = "Arn"

        enum_spec = ('list_namespaces', 'Namespaces', None)

        # get_namespace is the op to call
        # Id is the name of the parementer field in the detail call args to populate
        # Id is the key which is present in the enum response to map into the call arg
        # Namespace is the path in the response to pull out and merge into the list
        # response as the final product.
        detail_spec = ('get_namespace', 'Id', 'Id', 'Namespace')

        # refers to a field in the metadata response of the describe function
        # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/servicediscovery/client/get_namespace.html
        date = 'CreateDate'
