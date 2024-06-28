# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from c7n.reports.csvout import Formatter
from .apicallcaptor import ApiCallCaptor
from c7n.resources.servicediscovery import ServiceDiscoveryNamespace
from .common import BaseTest, event_data


class TestServiceDiscoveryNamespace(BaseTest):
    def test_servicediscovery_namespace(self):
        # session_factory = self.record_flight_data('test_servicediscovery_namespace')
        session_factory = self.replay_flight_data('test_servicediscovery_namespace')

        # test tags are populated and also the "spec" section
        p = self.load_policy(
            {
                "name": "servicediscovery-namespace-policy",
                "resource": "servicediscovery-namespace",
                "filters": [
                    {
                        "not": [{
                            "type": "value",
                            "key": "Name",
                            "op": "regex",
                            "value": r"^.*\.local$"
                        }]
                    }
                ]

            },
            session_factory=session_factory
        )

        captor = ApiCallCaptor.start_capture()
        # RUN THE SUT
        resources = p.run()

        self.assertEqual(
            [{"Tags": [{'Key': 'MODULE_NAME', 'Value': 'ecs-cluster'},
                           {'Key': 'ECS_CLUSTER', 'Value': 'EC1'}],
                    "Id": "ns-2",
                    "Arn": "arn:aws:servicediscovery:us-east-1:644160558196:namespace/ns-2",
                    "Name": "testEc2Cluster",
                    "Type": "HTTP",
                    "Description": "all services will be registered under this common namespace",
                    "Properties": {
                        "DnsProperties": {
                            "SOA": {}
                        },
                        "HttpProperties": {
                            "HttpName": "testEc2Cluster"
                        }
                    },
                    "CreateDate": "2023-11-03T02:36:27.877000+00:00",
                    "CreatorRequestId": "testEc2Cluster"
                }
             ],
            resources,
        )

        arns = p.resource_manager.get_arns(resources)
        self.assertEqual(
            [
                'arn:aws:servicediscovery:us-east-1:644160558196:namespace/ns-2'
            ],
            arns,
        )

        # The "placebo" testing library doesn't allow us to make assertions
        # linking specific api's calls to the specific mock response file
        # that will serve that request. So we will compensate here by
        # making an assertion about all the api calls and the order
        # of calls that must be made.
        self.assertEqual(
            [
                {'operation': 'ListNamespaces', 'params': {}, 'service': 'servicediscovery'},
                {'operation': 'GetNamespace',
                 'params': {'Id': 'ns-1'},
                 'service': 'servicediscovery'},
                {'operation': 'GetNamespace',
                 'params': {'Id': 'ns-2'},
                 'service': 'servicediscovery'},
                {
                    'operation': 'GetResources',
                    'params': {
                        'ResourceARNList': [
                            'arn:aws:servicediscovery:us-east-1:644160558196:namespace/ns-1',
                            'arn:aws:servicediscovery:us-east-1:644160558196:namespace/ns-2'
                        ]
                    },
                    'service': 'resourcegroupstaggingapi',
                },

            ],
            captor.calls,
        )

    def test_servicediscovery_namespace_event(self):
        session_factory = self.replay_flight_data('test_servicediscovery_namespace_event')

        p = self.load_policy(
            {
                "name": "servicediscovery-namespace-policy",
                "resource": "servicediscovery-namespace",
                "mode": {
                    "type": "cloudtrail",
                    "role": "CloudCustodian",
                    "events": [
                        {
                            "source": "servicediscovery.amazonaws.com",
                            "event": "CreatePrivateDnsNamespace",
                            "ids": "requestParameters.name",
                        }
                    ],
                },
                "filters": [
                    {
                        "not": [{
                            "type": "value",
                            "key": "Name",
                            "op": "regex",
                            "value": r".*\.local$"
                        }]
                    }
                ]

            },
            session_factory=session_factory
        )

        # event_data() names a file in tests/data/cwe that will drive the test execution.
        # file contains an event matching that which AWS would generate in cloud trail.
        event = {
            "detail": event_data("event-servicediscovery-namespace-create-namespace.json"),
            "debug": True,
        }

        captor = ApiCallCaptor.start_capture()

        # RUN THE SUT
        resources = p.push(event, None)

        self.assertEqual(
            [{"Tags": [{'Key': 'MODULE_NAME', 'Value': 'ecs-cluster'},
                        {'Key': 'ECS_CLUSTER', 'Value': 'EC1'}],
                "Id": "ns-1",
                "Arn": "arn:aws:servicediscovery:us-east-1:644160558196:namespace/ns-1",
                "Name": "testnik",
                "Type": "DNS_PRIVATE",
                "Description": "all services will be registered under this common namespace",
                "Properties": {
                    "DnsProperties": {
                        "HostedZoneId": "Z03288441NHEED4TM6QWT",
                        "SOA": {
                            "TTL": 15
                        }
                    },
                    "HttpProperties": {
                        "HttpName": "testnik.local"
                    }
                },
                "CreateDate": "2023-11-03T02:36:27.877000+00:00",
                "CreatorRequestId": "terraform-20240416094214796100000001"
                }
             ],
            resources,
        )
        # These assertions are necessary to be sure that the "get_arns" function is correctly
        # deriving the ARN.
        # See the documentation on the "arn" field in appmesh.py.
        arns = p.resource_manager.get_arns(resources)
        self.assertEqual(['arn:aws:servicediscovery:us-east-1:644160558196:namespace/ns-1'], arns)

        # The "placebo" testing library doesn't allow us to make assertions
        # linking specific api's calls to the specific mock response file
        # that will serve that request. So we will compensate here by
        # making an assertion about all the api calls and the order
        # of calls that must be made.

        self.assertEqual(
            [
                {'operation': 'ListNamespaces', 'params': {}, 'service': 'servicediscovery'},
                {'operation': 'GetNamespace',
                 'params': {'Id': 'ns-1'},
                 'service': 'servicediscovery'},
                {
                    'operation': 'GetResources',
                    'params': {
                        'ResourceARNList': [
                            'arn:aws:servicediscovery:us-east-1:644160558196:namespace/ns-1'
                        ]
                    },
                    'service': 'resourcegroupstaggingapi',
                },

            ],
            captor.calls,
        )

    def test_reporting(self):
        f = Formatter(resource_type=ServiceDiscoveryNamespace.resource_type)

        # provide a fake resource
        report = f.to_csv(
            records=[{
                "Id": "ns-1",
                "Arn": "arn:aws:servicediscovery:us-east-1:644160558196:namespace/ns-1",
                "Name": "testnik.local",
                "Type": "DNS_PRIVATE",
                "Description": "all services will be registered under this common namespace",
                "Properties": {
                    "DnsProperties": {
                        "HostedZoneId": "Z03288441NHEED4TM6QWT",
                        "SOA": {
                            "TTL": 15
                        }
                    },
                    "HttpProperties": {
                        "HttpName": "testnik.local"
                    }
                },
                "CreateDate": "2023-11-03T02:36:27.877000+00:00",
                "CreatorRequestId": "terraform-20240416094214796100000001"
                }
            ]
        )

        headers = list(f.headers())

        # expect Formatter to inspect the definition of certain
        # fields ("id", "name" and "date") from the AppMesh def
        # and to pick out those fields from a fake resource
        self.assertEqual(["Name", "CreateDate"],
                         headers, "header")

        # expect Formatter to inspect the definition of certain
        # fields ("name" and "date") from the AppMesh def
        # and to pick out those fields from a fake resource
        self.assertEqual([["testnik.local", "2023-11-03T02:36:27.877000+00:00"]], report)
