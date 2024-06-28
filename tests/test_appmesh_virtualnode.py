# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from c7n.reports.csvout import Formatter
from c7n.resources.appmesh import AppmeshVirtualNode
from .apicallcaptor import ApiCallCaptor
from .common import BaseTest, event_data


# during recording create some sample resources in AWS then
# set use a flight recorder and set the config region to wherever you want to read state from.
# this will create recording files in the placebo dir.
# session_factory = self.record_flight_data('test_appmesh_virtualgateway')
# config = Config.empty(region="eu-west-2")

# File names in the placebo directory follow the pattern <servicename>.<OperationName>_<call#>.json
# So boto3 "AppMesh.Client.describe_mesh()" becomes "appmesh.DescribeMesh"
# and the _<call#> suffix corresponds with the file to load for each call to that api.
class TestAppmeshVirtualNode(BaseTest):
    def test_appmesh_virtualnode(self):
        session_factory = self.replay_flight_data('test_appmesh_virtualnode')
        # session_factory = self.record_flight_data('test_appmesh_virtualnode')

        # https://boto3.amazonaws.com/v1/documentation/api/1.26.97/reference/services/appmesh/client/describe_virtual_node.html
        p = self.load_policy(
            {
                "name": "appmesh-node-policy",
                "resource": "aws.appmesh-virtualnode",
                "filters": [
                    {
                        "type": "value",
                        "key": "spec.backendDefaults.clientPolicy.tls.enforce",
                        "op": "eq",
                        "value": True,
                    }
                ],
            },
            session_factory=session_factory,
        )

        captor = ApiCallCaptor.start_capture()

        # RUN THE SUT
        resources = p.run()
        resources.sort(key=lambda r: r['metadata']['arn'])

        self.assertEqual(
            [{'Tags': [{'Key': 'MyTag', 'Value': 'MyValue'}],
              'c7n:MatchedFilters': ['spec.backendDefaults.clientPolicy.tls.enforce'],
              'meshName': 'm1',
              'metadata': {'arn': 'arn:aws:appmesh:us-east-1:659775036450:mesh/m1/virtualNode/vn1',
                           'createdAt': '2024-03-22T23:14:07.869000+00:00',
                           'lastUpdatedAt': '2024-03-22T23:28:19.231000+00:00',
                           'meshOwner': '659775036450',
                           'resourceOwner': '659775036451',
                           'uid': 'deab3c0d-37a9-4ec2-b690-594f27af3b24',
                           'version': 2},
              'spec': {'backendDefaults':
                           {'clientPolicy':
                                {'tls':
                                     {'enforce': True,
                                      'ports': [],
                                      'validation':
                                          {'trust':
                                               {'file':
                                                    {'certificateChain': '/the/capath'}
                                                }}}}},
                       'backends': [],
                       'listeners': [{'portMapping': {'port': 123, 'protocol': 'http'}}],
                       'logging': {},
                       'serviceDiscovery': {'dns': {'hostname': 'vn1.hostname'}}},
              'status': {'status': 'ACTIVE'},
              'virtualNodeName': 'vn1'}]
            ,
            resources,
        )

        # These assertions are necessary to be sure that the "get_arns" function is correctly
        # deriving the ARN.
        # See the documentation on the "arn" field in appmesh.py.
        arns = p.resource_manager.get_arns(resources)
        self.assertEqual(['arn:aws:appmesh:us-east-1:659775036450:mesh/m1/virtualNode/vn1'], arns)

        # The "placebo" testing library doesn't allow us to make assertions
        # linking specific api's calls to the specific mock response file
        # that will serve that request. So we will compensate here by
        # making an assertion about all the api calls and the order
        # of calls that must be made.
        self.assertEqual(
            [
                {'operation': 'ListMeshes', 'params': {}, 'service': 'appmesh'},
                {
                    'operation': 'ListVirtualNodes',
                    'params': {'meshName': 'm1'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'DescribeVirtualNode',
                    'params': {'meshName': 'm1', 'virtualNodeName': 'vn1'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'DescribeVirtualNode',
                    'params': {'meshName': 'm1', 'virtualNodeName': 'vn2'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'GetResources',
                    'params': {
                        'ResourceARNList': [
                            'arn:aws:appmesh:us-east-1:659775036450:mesh/m1/virtualNode/vn1',
                            'arn:aws:appmesh:us-east-1:659775036450:mesh/m1/virtualNode/vn2',
                        ]
                    },
                    'service': 'resourcegroupstaggingapi',
                },
            ],
            captor.calls,
        )

    def test_appmesh_virtualnode_event(self):
        session_factory = self.replay_flight_data('test_appmesh_virtualnode_event')
        p = self.load_policy(
            {
                "name": "appmesh-node-policy",
                "resource": "aws.appmesh-virtualnode",
                "mode": {
                    "type": "cloudtrail",
                    "role": "CloudCustodian",
                    "events": [
                        {
                            "source": "appmesh.amazonaws.com",
                            "event": "CreateVirtualNode",
                            "ids": "responseElements.virtualNode.metadata.arn",
                        }
                    ],
                },
                "filters": [
                    {
                        "type": "value",
                        "key": "spec.backendDefaults.clientPolicy.tls.enforce",
                        "op": "eq",
                        "value": True,
                    }
                ]
            },
            session_factory=session_factory,
        )

        # event_data() names a file in tests/data/cwe that will drive the test execution.
        # file contains an event matching that which AWS would generate in cloud trail.
        event = {
            "detail": event_data("event-appmesh-create-virtualnode.json"),
            "debug": True,
        }

        captor = ApiCallCaptor.start_capture()

        # RUN THE SUT
        resources = p.push(event, None)

        self.assertEqual(
            [{'Tags': [{'Key': 'MyTag', 'Value': 'MyValue'}],
              'c7n:MatchedFilters': ['spec.backendDefaults.clientPolicy.tls.enforce'],
              'meshName': 'm1',
              'metadata': {'arn': 'arn:aws:appmesh:us-east-1:659775036450:mesh/m1/virtualNode/vn1',
                           'createdAt': '2024-03-22T23:14:07.869000+00:00',
                           'lastUpdatedAt': '2024-03-22T23:28:19.231000+00:00',
                           'meshOwner': '659775036450',
                           'resourceOwner': '659775036450',
                           'uid': 'deab3c0d-37a9-4ec2-b690-594f27af3b24',
                           'version': 2},
              'spec': {'backendDefaults':
                           {'clientPolicy':
                                {'tls':
                                     {'enforce': True,
                                      'ports': [],
                                      'validation': {'trust': {'file': {
                                          'certificateChain': '/the/capath'}}}}}},
                       'backends': [],
                       'listeners': [{'portMapping': {'port': 123, 'protocol': 'http'}}],
                       'logging': {},
                       'serviceDiscovery': {'dns': {'hostname': 'vn1.hostname'}}},
              'status': {'status': 'ACTIVE'},
              'virtualNodeName': 'vn1'}]
            ,
            resources,
        )

        # These assertions are necessary to be sure that the "get_arns" function is
        # correctly deriving the ARN.
        # See the documentation on the "arn" field in appmesh.py.
        arns = p.resource_manager.get_arns(resources)
        self.assertEqual(['arn:aws:appmesh:us-east-1:659775036450:mesh/m1/virtualNode/vn1'], arns)

        # The "placebo" testing library doesn't allow us to make assertions
        # linking specific api's calls to the specific mock response file
        # that will serve that request. So we will compensate here by
        # making an assertion about all the api calls and the order
        # of calls that must be made.
        self.assertEqual(
            [
                {
                    'operation': 'DescribeVirtualNode',
                    'params': {'meshName': 'm1', 'virtualNodeName': 'vn1'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'GetResources',
                    'params': {
                        'ResourceARNList': [
                            'arn:aws:appmesh:us-east-1:659775036450:mesh/m1/virtualNode/vn1'
                        ]
                    },
                    'service': 'resourcegroupstaggingapi',
                },
            ],
            captor.calls,
        )

    def test_reporting(self):
        f = Formatter(resource_type=AppmeshVirtualNode.resource_type,
                      extra_fields=["mesh=meshName"])

        # provide a fake resource
        report = f.to_csv(
            records=[
                {'Tags': [{'Key': 'MyTag', 'Value': 'MyValue'}],
                 'c7n:MatchedFilters': ['spec.backendDefaults.clientPolicy.tls.enforce'],
                 'meshName': 'm1',
                 'metadata':
                     {'arn': 'arn:aws:appmesh:us-east-1:659775036450:mesh/m1/virtualNode/vn1',
                      'createdAt': '2024-03-22T23:14:07.869000+00:00',
                      'lastUpdatedAt': '2024-03-22T23:28:19.231000+00:00',
                      'meshOwner': '659775036450',
                      'resourceOwner': '659775036450',
                      'uid': 'deab3c0d-37a9-4ec2-b690-594f27af3b24',
                      'version': 2},
                 'spec': {'backendDefaults':
                              {'clientPolicy':
                                   {'tls':
                                        {'enforce': True,
                                         'ports': [],
                                         'validation': {'trust': {'file': {
                                             'certificateChain': '/the/capath'}}}}}},
                          'backends': [],
                          'listeners': [{'portMapping': {'port': 123, 'protocol': 'http'}}],
                          'logging': {},
                          'serviceDiscovery': {'dns': {'hostname': 'vn1.hostname'}}},
                 'status': {'status': 'ACTIVE'},
                 'virtualNodeName': 'vn1'}
            ],
        )

        headers = list(f.headers())

        # expect Formatter to inspect the definition of certain
        # fields ("id", "name" and "date") from the AppMesh def
        # and to pick out those fields from a fake resource
        self.assertEqual(["metadata.arn", "virtualNodeName", "metadata.createdAt", "mesh"],
                         headers, "header")

        self.assertEqual([["arn:aws:appmesh:us-east-1:659775036450:mesh/m1/virtualNode/vn1",
                           "vn1",
                           "2024-03-22T23:14:07.869000+00:00",
                           "m1"]
                          ], report, "data")

    def test_appmesh_virtualnode_meshowner_resourceowner(self):
        session_factory = self.replay_flight_data('test_appmesh_virtualnode')

        p = self.load_policy(
            {
                "name": "appmesh-node-policy",
                "resource": "aws.appmesh-virtualnode",
                "filters": [
                    {
                        "type": "value",
                        "key": "metadata.meshOwner",
                        "op": "ne",
                        "value": "metadata.resourceOwner",
                        "value_type": "expr"
                    }
                ],
            },
            session_factory=session_factory,
        )

        # RUN THE SUT
        resources = p.run()
        resources.sort(key=lambda r: r['metadata']['arn'])

        self.assertEqual(
            [{'Tags': [{'Key': 'MyTag', 'Value': 'MyValue'}],
              'c7n:MatchedFilters': ['metadata.meshOwner'],
              'meshName': 'm1',
              'metadata': {'arn': 'arn:aws:appmesh:us-east-1:659775036450:mesh/m1/virtualNode/vn1',
                           'createdAt': '2024-03-22T23:14:07.869000+00:00',
                           'lastUpdatedAt': '2024-03-22T23:28:19.231000+00:00',
                           'meshOwner': '659775036450',
                           'resourceOwner': '659775036451',
                           'uid': 'deab3c0d-37a9-4ec2-b690-594f27af3b24',
                           'version': 2},
              'spec': {'backendDefaults':
                           {'clientPolicy':
                                {'tls':
                                     {'enforce': True,
                                      'ports': [],
                                      'validation':
                                          {'trust':
                                               {'file':
                                                    {'certificateChain': '/the/capath'}
                                                }}}}},
                       'backends': [],
                       'listeners': [{'portMapping': {'port': 123, 'protocol': 'http'}}],
                       'logging': {},
                       'serviceDiscovery': {'dns': {'hostname': 'vn1.hostname'}}},
              'status': {'status': 'ACTIVE'},
              'virtualNodeName': 'vn1'}]
            ,
            resources,
        )
