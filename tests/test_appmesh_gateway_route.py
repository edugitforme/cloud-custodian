# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from c7n.reports.csvout import Formatter
from c7n.resources.appmesh import AppmeshGatewayRoute
from .apicallcaptor import ApiCallCaptor
from .common import BaseTest, event_data


# during recording create some sample resources in AWS then
# set use a flight recorder and set the config region to wherever you want to read state from.
# this will create recording files in the placebo dir.
# session_factory = self.record_flight_data('test_appmesh_gateway_route')
# config = Config.empty(region="eu-west-2")

# File names in the placebo directory follow the pattern <servicename>.<OperationName>_<call#>.json
# So boto3 "AppMesh.Client.describe_mesh()" becomes "appmesh.DescribeMesh"
# and the _<call#> suffix corresponds with the file to load for each call to that api.

class TestAppmeshGatewayRoute(BaseTest):
    def test_appmesh_gateway_route(self):
        session_factory = self.replay_flight_data('test_appmesh_gateway_route')

        # test data has 2 VGW but only 1 has a port of 123
        p = self.load_policy(
            {
                "name": "appmesh-gateway-route-policy",
                "resource": "aws.appmesh-gateway-route",
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

        captor = ApiCallCaptor.start_capture()

        # RUN THE SUT
        resources = p.run()
        resources.sort(key=lambda r: r['metadata']['arn'])

        self.assertEqual(
            [{'Tags': [{'Key': 'MODULE_NAME', 'Value': 'ecs-application'},
                           {'Key': 'ECS_APPLICATION', 'Value': 'ec1'}],
              'c7n:MatchedFilters': ['metadata.meshOwner'],
              "gatewayRouteName": "gr2",
              "meshName": "m1",
              "metadata": {
                  "arn":
                    "arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualGateway/vg2/gatewayRoute/gr2",
                  "createdAt": "2023-11-03T02:36:27.877000+00:00",
                  "lastUpdatedAt": "2023-11-03T02:36:27.877000+00:00",
                  "meshOwner": "644160558196",
                  "resourceOwner": "644160558198",
                  "uid": "4bcb98dc-2168-4dcc-a9ba-cbbcddbb55f8",
                  "version": 1
              },
              "spec": {
                  "httpRoute": {
                      "action": {
                          "rewrite": {
                              "hostname": {
                                  "defaultTargetHostname": "DISABLED"
                              },
                              "prefix": {
                                  "defaultPrefix": "DISABLED"
                              }
                          },
                          "target": {
                              "port": 8080,
                              "virtualService": {
                                  "virtualServiceName": "vs2"
                              }
                          }
                      },
                      "match": {
                          "hostname": {
                              "exact": "ec1.test.aws.net"
                          },
                          "prefix": "/"
                      }
                  }
              },
              "status": {
                  "status": "ACTIVE"
              },
              "virtualGatewayName": "vg2"}],
            resources,
        )

        # These assertions are necessary to be sure that the "get_arns" function is correctly
        # deriving the ARN.
        # See the documentation on the "arn" field in appmesh.py.
        arns = p.resource_manager.get_arns(resources)
        self.assertEqual(
            ['arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualGateway/vg2/gatewayRoute/gr2'],
            arns)

        # The "placebo" testing library doesn't allow us to make assertions
        # linking specific api's calls to the specific mock response file
        # that will serve that request. So we will compensate here by
        # making an assertion about all the api calls and the order
        # of calls that must be made.
        self.assertEqual(
            [
                {'operation': 'ListMeshes', 'params': {}, 'service': 'appmesh'},
                {
                    'operation': 'ListVirtualGateways',
                    'params': {'meshName': 'm1'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'ListVirtualGateways',
                    'params': {'meshName': 'm2'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'ListGatewayRoutes',
                    'params': {'meshName': 'm1', 'virtualGatewayName': 'vg1'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'DescribeGatewayRoute',
                    'params': {'meshName': 'm1',
                               'virtualGatewayName': 'vg1',
                               'gatewayRouteName': 'gr1'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'ListGatewayRoutes',
                    'params': {'meshName': 'm1', 'virtualGatewayName': 'vg2'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'DescribeGatewayRoute',
                    'params': {'meshName': 'm1',
                               'virtualGatewayName': 'vg2',
                               'gatewayRouteName': 'gr2'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'GetResources',
                    'params': {
                        'ResourceARNList': [
                            'arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualGateway/vg1/gatewayRoute/gr1',
                            'arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualGateway/vg2/gatewayRoute/gr2',
                        ]
                    },
                    'service': 'resourcegroupstaggingapi',
                },
            ],
            captor.calls,
        )

    def test_appmesh_gateway_route_event(self):
        session_factory = self.replay_flight_data('test_appmesh_gateway_route_event')
        p = self.load_policy(
            {
                "name": "appmesh-gateway-route-policy",
                "resource": "aws.appmesh-gateway-route",
                "mode": {
                    "type": "cloudtrail",
                    "role": "CloudCustodian",
                    "events": [
                        {
                            "source": "appmesh.amazonaws.com",
                            "event": "CreateGatewayRoute",
                            "ids": "detail.responseElements.gatewayRoute.metadata.arn",
                        }
                    ],
                },
                "filters": [
                    {
                        "type": "event",
                        "key": "detail.responseElements.gatewayRoute.metadata.meshOwner",
                        "op": "ne",
                        "value": "detail.responseElements.gatewayRoute.metadata.resourceOwner",
                        "value_type": "expr"
                    }
                ]

            },
            session_factory=session_factory,
        )

        # event_data() names a file in tests/data/cwe that will drive the test execution.
        # file contains an event matching that which AWS would generate in cloud trail.
        event = {
            "detail": event_data("event-appmesh-create-gateway-route.json"),
            "debug": True,
        }

        captor = ApiCallCaptor.start_capture()

        # RUN THE SUT
        resources = p.push(event, None)

        self.assertEqual(
            [{'Tags': [{'Key': 'MODULE_NAME', 'Value': 'ecs-application'},
                            {'Key': 'ECS_APPLICATION', 'Value': 'ec1'}],
              "gatewayRouteName": "gr1",
              "meshName": "m1",
              "metadata": {
                  "arn":
                    "arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualGateway/vg1/gatewayRoute/gr1",
                  "createdAt": "2023-11-03T02:36:27.877000+00:00",
                  "lastUpdatedAt": "2023-11-03T02:36:27.877000+00:00",
                  "meshOwner": "644160558196",
                  "resourceOwner": "644160558198",
                  "uid": "4bcb98dc-2168-4dcc-a9ba-cbbcddbb55f8",
                  "version": 1
              },
              "spec": {
                  "httpRoute": {
                      "action": {
                          "rewrite": {
                              "hostname": {
                                  "defaultTargetHostname": "DISABLED"
                              },
                              "prefix": {
                                  "defaultPrefix": "DISABLED"
                              }
                          },
                          "target": {
                              "port": 8080,
                              "virtualService": {
                                  "virtualServiceName": "vs1"
                              }
                          }
                      },
                      "match": {
                          "hostname": {
                              "exact": "ec1.test.aws.net"
                          },
                          "prefix": "/"
                      }
                  }
              },
              "status": {
                  "status": "ACTIVE"
              },
              "virtualGatewayName": "vg1"}],
            resources,
        )

        # These assertions are necessary to be sure that the "get_arns" function is correctly
        # deriving the ARN.
        # See the documentation on the "arn" field in appmesh.py.
        arns = p.resource_manager.get_arns(resources)
        self.assertEqual(
            ['arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualGateway/vg1/gatewayRoute/gr1'],
            arns)

        # The "placebo" testing library doesn't allow us to make assertions
        # linking specific api's calls to the specific mock response file
        # that will serve that request. So we will compensate here by
        # making an assertion about all the api calls and the order
        # of calls that must be made.
        self.assertEqual(
            [
                {
                    'operation': 'ListGatewayRoutes',
                    'params': {'meshName': 'm1', 'virtualGatewayName': 'vg1'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'DescribeGatewayRoute',
                    'params': {'meshName': 'm1',
                               'virtualGatewayName': 'vg1',
                               'gatewayRouteName': 'gr1'},

                    'service': 'appmesh',
                },
                {
                    'operation': 'GetResources',
                    'params': {
                        'ResourceARNList': [
                            'arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualGateway/vg1/gatewayRoute/gr1'
                        ]
                    },
                    'service': 'resourcegroupstaggingapi',
                },
            ],
            captor.calls,
        )

    def test_reporting(self):
        f = Formatter(resource_type=AppmeshGatewayRoute.resource_type,
                      extra_fields=["mesh=meshName"])

        # provide a fake resource
        report = f.to_csv(
            records=[
                {'Tags': [{'Key': 'MODULE_NAME', 'Value': 'ecs-application'},
                          {'Key': 'ECS_APPLICATION', 'Value': 'ec1'}],
                  "gatewayRouteName": "gr1",
                  "meshName": "m1",
                  "metadata": {
                      "arn":
                        "arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualGateway/vg1/gatewayRoute/gr1",
                      "createdAt": "2023-11-03T02:36:27.877000+00:00",
                      "lastUpdatedAt": "2023-11-03T02:36:27.877000+00:00",
                      "meshOwner": "644160558196",
                      "resourceOwner": "644160558198",
                      "uid": "4bcb98dc-2168-4dcc-a9ba-cbbcddbb55f8",
                      "version": 1
                  },
                  "spec": {
                      "httpRoute": {
                          "action": {
                              "rewrite": {
                                  "hostname": {
                                      "defaultTargetHostname": "DISABLED"
                                  },
                                  "prefix": {
                                      "defaultPrefix": "DISABLED"
                                  }
                              },
                              "target": {
                                  "port": 8080,
                                  "virtualService": {
                                      "virtualServiceName": "vs1"
                                  }
                              }
                          },
                          "match": {
                              "hostname": {
                                  "exact": "ec1.test.aws.net"
                              },
                              "prefix": "/"
                          }
                      }
                  },
                  "status": {
                      "status": "ACTIVE"
                  },
                  "virtualGatewayName": "vg1"},
            ],
        )

        headers = list(f.headers())

        # expect Formatter to inspect the definition of certain
        # fields ("id", "name" and "date") from the AppMesh def
        # and to pick out those fields from a fake resource
        self.assertEqual(["metadata.arn", "gatewayRouteName", "metadata.createdAt", "mesh"],
                         headers, "header")

        self.assertEqual([["arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualGateway/vg1/gatewayRoute/gr1",
                           "gr1",
                           "2023-11-03T02:36:27.877000+00:00",
                           "m1"]
                          ], report, "data")
