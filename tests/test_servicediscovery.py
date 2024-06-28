# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from c7n.reports.csvout import Formatter
from .apicallcaptor import ApiCallCaptor
from c7n.resources.servicediscovery import ServiceDiscovery
from .common import BaseTest, event_data


class TestServiceDiscovery(BaseTest):
    def test_servicediscovery(self):
        # session_factory = self.record_flight_data('test_servicediscovery')
        session_factory = self.replay_flight_data('test_servicediscovery')

        # test tags are populated and also the "spec" section

        p = self.load_policy(
            {
                "name": "servicediscovery-policy",
                "resource": "aws.servicediscovery"
            },
            session_factory=session_factory
        )

        captor = ApiCallCaptor.start_capture()
        # RUN THE SUT
        resources = p.run()

        self.assertEqual(
            [{'Tags': [{'Key': 'MODULE_NAME', 'Value': 'ecs-cluster'},
                       {'Key': 'ECS_CLUSTER', 'Value': 'EC1'}],
              'Id': 'srv-1',
              "Arn": "arn:aws:servicediscovery:us-east-1:644160558196:service/srv-1",
              "Name": "service1",
              "NamespaceId": "ns-1",
              "DnsConfig": {
                  "NamespaceId": "ns-1",
                  "RoutingPolicy": "WEIGHTED",
                  "DnsRecords": [
                      {
                          "Type": "CNAME",
                          "TTL": 10
                      }
                  ]
              },
              'HealthCheckCustomConfig': {'FailureThreshold': 1},
              "Type": "DNS_HTTP",
              "CreateDate": "2023-11-03T02:36:27.877000+00:00",
              "CreatorRequestId": "terraform-2024041915345708160000001a"},
             {'Tags': [{'Key': 'MODULE_NAME', 'Value': 'ecs-cluster'},
                       {'Key': 'ECS_CLUSTER', 'Value': 'EC1'}],
              'Id': 'srv-2',
              "Arn": "arn:aws:servicediscovery:us-east-1:644160558196:service/srv-2",
              "Name": "service2",
              "NamespaceId": "ns-2",
              "DnsConfig": {
                  "NamespaceId": "ns-2",
                  "RoutingPolicy": "WEIGHTED",
                  "DnsRecords": [
                      {
                          "Type": "CNAME",
                          "TTL": 10
                      }
                  ]
              },
              'HealthCheckCustomConfig': {'FailureThreshold': 1},
              "Type": "DNS_HTTP",
              "CreateDate": "2023-11-03T02:36:27.877000+00:00",
              "CreatorRequestId": "terraform-2024031213135212710000000c"},
             ],
            resources,
        )

        # These assertions are necessary to be sure that the "get_arns" function is correctly
        # deriving the ARN.
        # See the documentation on the "arn" field in appmesh.py.
        arns = p.resource_manager.get_arns(resources)
        self.assertEqual(
            [
                'arn:aws:servicediscovery:us-east-1:644160558196:service/srv-1',
                'arn:aws:servicediscovery:us-east-1:644160558196:service/srv-2'
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
                {'operation': 'ListServices', 'params': {}, 'service': 'servicediscovery'},
                {'operation': 'GetService',
                 'params': {'Id': 'srv-1'},
                 'service': 'servicediscovery'},
                {'operation': 'GetService',
                 'params': {'Id': 'srv-2'},
                 'service': 'servicediscovery'},
                {
                    'operation': 'GetResources',
                    'params': {
                        'ResourceARNList': [
                            'arn:aws:servicediscovery:us-east-1:644160558196:service/srv-1',
                            'arn:aws:servicediscovery:us-east-1:644160558196:service/srv-2'
                        ]
                    },
                    'service': 'resourcegroupstaggingapi',
                },
            ],
            captor.calls,
        )

    def test_servicediscovery_event(self):
        session_factory = self.replay_flight_data('test_servicediscovery_event')

        p = self.load_policy(
            {
                "name": "servicediscovery-policy",
                "resource": "aws.servicediscovery",
                "mode": {
                    "type": "cloudtrail",
                    "role": "CloudCustodian",
                    "events": [
                        {
                            "source": "servicediscovery.amazonaws.com",
                            "event": "CreateService",
                            "ids": "responseElements.service.id",
                        }
                    ],
                }
            },
            session_factory=session_factory
        )

        # event_data() names a file in tests/data/cwe that will drive the test execution.
        # file contains an event matching that which AWS would generate in cloud trail.
        event = {
            "detail": event_data("event-servicediscovery-create-service.json"),
            "debug": True,
        }

        captor = ApiCallCaptor.start_capture()

        # RUN THE SUT
        resources = p.push(event, None)
        resources.sort(key=lambda r: r["Arn"])

        self.assertEqual(
            [{'Tags': [{'Key': 'MODULE_NAME', 'Value': 'ecs-cluster'},
                          {'Key': 'ECS_CLUSTER', 'Value': 'EC1'}],
                 'Id': 'srv-1',
                 "Arn": "arn:aws:servicediscovery:us-east-1:644160558196:service/srv-1",
                 "Name": "service1",
                 "NamespaceId": "ns-1",
                 "DnsConfig": {
                     "NamespaceId": "ns-1",
                     "RoutingPolicy": "WEIGHTED",
                     "DnsRecords": [
                         {
                             "Type": "CNAME",
                             "TTL": 10
                         }
                     ]
                 },
                 'HealthCheckCustomConfig': {'FailureThreshold': 1},
                 "Type": "DNS_HTTP",
                 "CreateDate": "2023-11-03T02:36:27.877000+00:00",
                 "CreatorRequestId": "terraform-2024041915345708160000001a"}
            ],
            resources,
        )

        # These assertions are necessary to be sure that the "get_arns" function is correctly
        # deriving the ARN.
        # See the documentation on the "arn" field in appmesh.py.
        arns = p.resource_manager.get_arns(resources)
        self.assertEqual(['arn:aws:servicediscovery:us-east-1:644160558196:service/srv-1'], arns)

        # The "placebo" testing library doesn't allow us to make assertions
        # linking specific api's calls to the specific mock response file
        # that will serve that request. So we will compensate here by
        # making an assertion about all the api calls and the order
        # of calls that must be made.

        self.assertEqual(
            [
                {'operation': 'ListServices', 'params': {}, 'service': 'servicediscovery'},
                {'operation': 'GetService',
                 'params': {'Id': 'srv-1'},
                 'service': 'servicediscovery'},
                {
                    'operation': 'GetResources',
                    'params': {
                        'ResourceARNList': [
                            'arn:aws:servicediscovery:us-east-1:644160558196:service/srv-1'
                        ]
                    },
                    'service': 'resourcegroupstaggingapi',
                },
            ],
            captor.calls,
        )

    def test_reporting(self):
        f = Formatter(resource_type=ServiceDiscovery.resource_type)

        # provide a fake resource
        report = f.to_csv(
            records=[
                {
                    'Id': 'srv-1',
                    "Arn": "arn:aws:servicediscovery:us-east-1:644160558196:service/srv-1",
                    "Name": "service1",
                    "NamespaceId": "ns-1",
                    "DnsConfig": {
                        "NamespaceId": "ns-1",
                        "RoutingPolicy": "WEIGHTED",
                        "DnsRecords": [
                            {
                                "Type": "CNAME",
                                "TTL": 10
                            }
                        ]
                    },
                    'HealthCheckCustomConfig': {'FailureThreshold': 1},
                    "Type": "DNS_HTTP",
                    "CreateDate": "2023-11-03T02:36:27.877000+00:00",
                    "CreatorRequestId": "terraform-2024041915345708160000001a"
                }
            ]
        )

        headers = list(f.headers())

        # expect Formatter to inspect the definition of certain
        # fields ("id", "name" and "date") from the AppMesh def
        # and to pick out those fields from a fake resource
        self.assertEqual(["Id", "Name", "CreateDate"],
                         headers, "header")

        # expect Formatter to inspect the definition of certain
        # fields ("name" and "date") from the AppMesh def
        # and to pick out those fields from a fake resource
        self.assertEqual([["srv-1", "service1", "2023-11-03T02:36:27.877000+00:00"]], report)
