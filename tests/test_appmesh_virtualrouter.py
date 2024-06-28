# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from c7n.reports.csvout import Formatter
from c7n.resources.appmesh import AppmeshVirtualRouter
from .apicallcaptor import ApiCallCaptor
from .common import BaseTest, event_data


# during recording create some sample resources in AWS then
# set use a flight recorder and set the config region to wherever you want to read state from.
# this will create recording files in the placebo dir.
# session_factory = self.record_flight_data('test_appmesh_virtualrouter')
# config = Config.empty(region="eu-west-2")

# File names in the placebo directory follow the pattern <servicename>.<OperationName>_<call#>.json
# So boto3 "AppMesh.Client.describe_mesh()" becomes "appmesh.DescribeMesh"
# and the _<call#> suffix corresponds with the file to load for each call to that api.

class TestAppmeshVirtualRouter(BaseTest):
    def test_appmesh_virtualrouter(self):
        session_factory = self.replay_flight_data('test_appmesh_virtualrouter')

        # test data has 2 VGW but only 1 has a port of 123
        p = self.load_policy(
            {
                "name": "appmesh-virtual-router-policy",
                "resource": "aws.appmesh-virtualrouter",
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
              'meshName': 'm1',
              'metadata': {
                  "arn": "arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualRouter/vr2",
                  "createdAt": "2023-11-03T02:36:27.877000+00:00",
                  "lastUpdatedAt": "2023-11-03T02:36:27.877000+00:00",
                  "meshOwner": "644160558196",
                  "resourceOwner": "644160558198",
                  "uid": "1355d652-663d-4862-9217-53c106a75272",
                  "version": 1
                   },
                  "spec": {
                      "listeners": [
                          {
                              "portMapping": {
                                  "port": 8080,
                                  "protocol": "http"
                              }
                          }
                      ]
                  },
                  "status": {
                      "status": "ACTIVE"
                  },
                  "virtualRouterName": "vr2"}],
            resources,
        )

        # These assertions are necessary to be sure that the "get_arns" function is correctly
        # deriving the ARN.
        # See the documentation on the "arn" field in appmesh.py.
        arns = p.resource_manager.get_arns(resources)
        self.assertEqual(['arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualRouter/vr2'], arns)

        # The "placebo" testing library doesn't allow us to make assertions
        # linking specific api's calls to the specific mock response file
        # that will serve that request. So we will compensate here by
        # making an assertion about all the api calls and the order
        # of calls that must be made.
        self.assertEqual(
            [
                {'operation': 'ListMeshes', 'params': {}, 'service': 'appmesh'},
                {
                    'operation': 'ListVirtualRouters',
                    'params': {'meshName': 'm1'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'ListVirtualRouters',
                    'params': {'meshName': 'm2'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'DescribeVirtualRouter',
                    'params': {'meshName': 'm1', 'virtualRouterName': 'vr1'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'DescribeVirtualRouter',
                    'params': {'meshName': 'm1', 'virtualRouterName': 'vr2'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'GetResources',
                    'params': {
                        'ResourceARNList': [
                            'arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualRouter/vr1',
                            'arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualRouter/vr2',
                        ]
                    },
                    'service': 'resourcegroupstaggingapi',
                },
            ],
            captor.calls,
        )

    def test_appmesh_virtualrouter_event(self):
        session_factory = self.replay_flight_data('test_appmesh_virtualrouter_event')
        p = self.load_policy(
            {
                "name": "appmesh-virtual-router-policy",
                "resource": "aws.appmesh-virtualrouter",
                "mode": {
                    "type": "cloudtrail",
                    "role": "CloudCustodian",
                    "events": [
                        {
                            "source": "appmesh.amazonaws.com",
                            "event": "CreateVirtualRouter",
                            "ids": "detail.responseElements.virtualRouter.metadata.arn",
                        }
                    ],
                },
                "filters": [
                    {
                        "type": "event",
                        "key": "detail.responseElements.virtualRouter.metadata.meshOwner",
                        "op": "ne",
                        "value": "detail.responseElements.virtualRouter.metadata.resourceOwner",
                        "value_type": "expr"
                    }
                ]

            },
            session_factory=session_factory,
        )

        # event_data() names a file in tests/data/cwe that will drive the test execution.
        # file contains an event matching that which AWS would generate in cloud trail.
        event = {
            "detail": event_data("event-appmesh-create-virtualrouter.json"),
            "debug": True,
        }

        captor = ApiCallCaptor.start_capture()

        # RUN THE SUT
        resources = p.push(event, None)

        self.assertEqual(
            [{'Tags': [{'Key': 'MODULE_NAME', 'Value': 'ecs-application'},
                           {'Key': 'ECS_APPLICATION', 'Value': 'ec1'}],
              "meshName": "m1",
              'metadata': {
                  "arn": "arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualRouter/vr1",
                  "createdAt": "2023-11-03T02:36:27.877000+00:00",
                  "lastUpdatedAt": "2023-11-03T02:36:27.877000+00:00",
                  "meshOwner": "644160558196",
                  "resourceOwner": "644160558198",
                  "uid": "1355d652-663d-4862-9217-53c106a75272",
                  "version": 1},
              "spec": {
                  "listeners": [
                      {
                          "portMapping": {
                              "port": 8080,
                              "protocol": "http"
                          }
                      }
                  ]
              },
              "status": {
                  "status": "ACTIVE"
              },
              "virtualRouterName": "vr1"}],
            resources,
        )

        # These assertions are necessary to be sure that the "get_arns" function is
        # correctly deriving the ARN.
        # See the documentation on the "arn" field in appmesh.py.
        arns = p.resource_manager.get_arns(resources)
        self.assertEqual(['arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualRouter/vr1'], arns)

        # The "placebo" testing library doesn't allow us to make assertions
        # linking specific api's calls to the specific mock response file
        # that will serve that request. So we will compensate here by
        # making an assertion about all the api calls and the order
        # of calls that must be made.
        self.assertEqual(
            [
                {
                    'operation': 'DescribeVirtualRouter',
                    'params': {'meshName': 'm1', 'virtualRouterName': 'vr1'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'GetResources',
                    'params': {
                        'ResourceARNList': [
                            'arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualRouter/vr1'
                        ]
                    },
                    'service': 'resourcegroupstaggingapi',
                },
            ],
            captor.calls,
        )

    def test_reporting(self):
        f = Formatter(resource_type=AppmeshVirtualRouter.resource_type,
                      extra_fields=["mesh=meshName"])

        # provide a fake resource
        report = f.to_csv(
            records=[
                {'Tags': [{'Key': 'MODULE_NAME', 'Value': 'ecs-application'},
                          {'Key': 'ECS_APPLICATION', 'Value': 'ec1'}],
                 'c7n:MatchedFilters': ['metadata.resourceOwner'],
                 'meshName': 'm1',
                 'metadata': {
                     "arn": "arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualRouter/vr1",
                     "createdAt": "2023-11-03T02:36:27.877000+00:00",
                     "lastUpdatedAt": "2023-11-03T02:36:27.877000+00:00",
                     "meshOwner": "644160558196",
                     "resourceOwner": "644160558198",
                     "uid": "1355d652-663d-4862-9217-53c106a75272",
                     "version": 1},
                 "spec": {
                     "listeners": [
                         {
                             "portMapping": {
                                 "port": 8080,
                                 "protocol": "http"
                             }
                         }
                     ]
                 },
                 "status": {
                     "status": "ACTIVE"
                 },
                 "virtualRouterName": "vr1"},
            ],
        )

        headers = list(f.headers())

        # expect Formatter to inspect the definition of certain
        # fields ("id", "name" and "date") from the AppMesh def
        # and to pick out those fields from a fake resource
        self.assertEqual(["metadata.arn", "virtualRouterName", "metadata.createdAt", "mesh"],
                         headers, "header")

        self.assertEqual([["arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualRouter/vr1",
                           "vr1",
                           "2023-11-03T02:36:27.877000+00:00",
                           "m1"]
                          ], report, "data")
