# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from c7n.reports.csvout import Formatter
from .apicallcaptor import ApiCallCaptor
from c7n.resources.servicediscovery import ServiceDiscoveryInstance
from .common import BaseTest, event_data


class TestServiceDiscoveryInstance(BaseTest):
    def test_servicediscovery_instance(self):
        # session_factory = self.record_flight_data('test_servicediscovery_instance')
        session_factory = self.replay_flight_data('test_servicediscovery_instance')

        # test tags are populated and also the "spec" section
        p = self.load_policy(
            {
                "name": "servicediscovery-instance-policy",
                "resource": "servicediscovery-instance",
                "filters": [
                    {
                        "or": [
                            {
                                "type": "value",
                                "key": "Attributes",
                                "value": "absent"
                            },
                            {
                                "type": "value",
                                "key": "Attributes.AWS_INSTANCE_CNAME",
                                "value": "absent"
                            },
                            {
                                "type": "value",
                                "key": "Attributes.AWS_INSTANCE_IPV4",
                                "value": "absent"
                            }
                        ]
                    }
                ]
            },
            session_factory=session_factory
        )

        captor = ApiCallCaptor.start_capture()
        # RUN THE SUT
        resources = p.run()

        self.assertEqual(
            [{'Attributes': {'AWS_INSTANCE_CNAME': 'ecs-proxy.ec1.us-east-1.local'},
              'Id': 'app.datadog-proxy',
              'c7n:MatchedFilters': ['Attributes.AWS_INSTANCE_IPV4']}
             ],
            resources,
        )

        arns = p.resource_manager.get_arns(resources)
        self.assertEqual(
            [
                'app.datadog-proxy'
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
                {'operation': 'ListInstances',
                 'params': {'ServiceId': 'srv-1'},
                 'service': 'servicediscovery'},
                {'operation': 'ListInstances',
                 'params': {'ServiceId': 'srv-2'},
                 'service': 'servicediscovery'}
            ],
            captor.calls,
        )

    def test_servicediscovery_instance_event(self):
        session_factory = self.replay_flight_data('test_servicediscovery_instance_event')

        p = self.load_policy(
            {
                "name": "servicediscovery-instance-policy",
                "resource": "servicediscovery-instance",
                "mode": {
                    "type": "cloudtrail",
                    "role": "CloudCustodian",
                    "events": [
                        {
                            "source": "servicediscovery.amazonaws.com",
                            "event": "RegisterInstance",
                            "ids": "requestParameters.instanceId",
                        }
                    ],
                },
                "filters": [
                    {
                        "or": [
                            {
                                "type": "value",
                                "key": "Attributes",
                                "value": "absent"
                            },
                            {
                                "type": "value",
                                "key": "Attributes.AWS_INSTANCE_CNAME",
                                "value": "absent"
                            },
                            {
                                "type": "value",
                                "key": "Attributes.AWS_INSTANCE_IPV4",
                                "value": "absent"
                            }
                        ]
                    }
                ]
            },
            session_factory=session_factory
        )

        # event_data() names a file in tests/data/cwe that will drive the test execution.
        # file contains an event matching that which AWS would generate in cloud trail.
        event = {
            "detail": event_data("event-servicediscovery-instance-register-instance.json"),
            "debug": True,
        }

        captor = ApiCallCaptor.start_capture()

        # RUN THE SUT
        resources = p.push(event, None)
        resources.sort(key=lambda r: r["Id"])

        self.assertEqual(
            [{'Attributes': {'type': 'eks'},
              'Id': 'aws:eks:us-east-1:644160558196:cluster/ins1',
              'c7n:MatchedFilters': ['Attributes.AWS_INSTANCE_CNAME',
                                     'Attributes.AWS_INSTANCE_IPV4']}
             ],
            resources,
        )
        # These assertions are necessary to be sure that the "get_arns" function is correctly
        # deriving the ARN.
        # See the documentation on the "arn" field in appmesh.py.
        arns = p.resource_manager.get_arns(resources)
        self.assertEqual(['aws:eks:us-east-1:644160558196:cluster/ins1'], arns)

        # The "placebo" testing library doesn't allow us to make assertions
        # linking specific api's calls to the specific mock response file
        # that will serve that request. So we will compensate here by
        # making an assertion about all the api calls and the order
        # of calls that must be made.

        self.assertEqual(
            [
                {'operation': 'ListServices', 'params': {}, 'service': 'servicediscovery'},
                {'operation': 'ListInstances',
                 'params': {'ServiceId': 'srv-1'},
                 'service': 'servicediscovery'}
            ],
            captor.calls,
        )

    def test_reporting(self):
        f = Formatter(resource_type=ServiceDiscoveryInstance.resource_type)

        # provide a fake resource
        report = f.to_csv(
            records=[
                {'Attributes': {"AWS_INSTANCE_CNAME": "ecs-proxy.ec1.us-east-1.local",
                                "AWS_INSTANCE_IPV4": "10.11.12.14"},
                 'Id': 'aws:eks:us-east-1:644160558196:cluster/ins1'
                }
            ]
        )

        headers = list(f.headers())

        # expect Formatter to inspect the definition of certain
        # fields ("id", "name" and "date") from the AppMesh def
        # and to pick out those fields from a fake resource
        self.assertEqual(["Id"],
                         headers, "header")

        # expect Formatter to inspect the definition of certain
        # fields ("name" and "date") from the AppMesh def
        # and to pick out those fields from a fake resource
        self.assertEqual([["aws:eks:us-east-1:644160558196:cluster/ins1"]], report)
