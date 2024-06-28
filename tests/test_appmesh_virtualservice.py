# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from c7n.reports.csvout import Formatter
from c7n.resources.appmesh import AppmeshVirtualService
from .apicallcaptor import ApiCallCaptor
from .common import BaseTest, event_data


# during recording create some sample resources in AWS then
# set use a flight recorder and set the config region to wherever you want to read state from.
# this will create recording files in the placebo dir.
# session_factory = self.record_flight_data('test_appmesh_virtualservice')
# config = Config.empty(region="eu-west-2")

# File names in the placebo directory follow the pattern <servicename>.<OperationName>_<call#>.json
# So boto3 "AppMesh.Client.describe_mesh()" becomes "appmesh.DescribeMesh"
# and the _<call#> suffix corresponds with the file to load for each call to that api.

class TestAppmeshVirtualService(BaseTest):
    def test_appmesh_virtualservice(self):
        session_factory = self.replay_flight_data('test_appmesh_virtualservice')

        # test data has 2 VGW but only 1 has a port of 123
        p = self.load_policy(
            {
                "name": "appmesh-virtual-service-policy",
                "resource": "aws.appmesh-virtualservice",
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
              "arn":
            "arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualService/vs2.m1.us-east-1.local",
              "createdAt": "2023-11-03T02:36:27.877000+00:00",
              "lastUpdatedAt": "2023-11-03T02:36:27.877000+00:00",
              "meshOwner": "644160558196",
              "resourceOwner": "644160558198",
              "uid": "f5b0ace5-d9e7-4f16-ac9c-44c30dc0ad30",
              "version": 1},
              "spec": {
                  "provider": {
                      "virtualRouter": {
                          "virtualRouterName": "vr2"
                      }
                  }
              },
              "status": {
                  "status": "ACTIVE"
              },
              "virtualServiceName": "vs2.m1.us-east-1.local"}],
        resources,
    )

        # These assertions are necessary to be sure that the "get_arns" function is correctly
        # deriving the ARN.
        # See the documentation on the "arn" field in appmesh.py.
        arns = p.resource_manager.get_arns(resources)
        self.assertEqual(
             ['arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualService/vs2.m1.us-east-1.local'],
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
                    'operation': 'ListVirtualServices',
                    'params': {'meshName': 'm1'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'ListVirtualServices',
                    'params': {'meshName': 'm2'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'DescribeVirtualService',
                    'params': {'meshName': 'm1', 'virtualServiceName': 'vs1.m1.us-east-1.local'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'DescribeVirtualService',
                    'params': {'meshName': 'm1', 'virtualServiceName': 'vs2.m1.us-east-1.local'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'GetResources',
                    'params': {
                        'ResourceARNList': [
                            'arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualService/vs1.m1.us-east-1.local',
                            'arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualService/vs2.m1.us-east-1.local',
                        ]
                    },
                    'service': 'resourcegroupstaggingapi',
                },
            ],
            captor.calls,
        )

    def test_appmesh_virtualservice_event(self):
        session_factory = self.replay_flight_data('test_appmesh_virtualservice_event')
        p = self.load_policy(
            {
                "name": "appmesh-virtual-service-policy",
                "resource": "aws.appmesh-virtualservice",
                "mode": {
                    "type": "cloudtrail",
                    "role": "CloudCustodian",
                    "events": [
                        {
                            "source": "appmesh.amazonaws.com",
                            "event": "CreateVirtualService",
                            "ids": "detail.responseElements.virtualService.metadata.arn",
                        }
                    ],
                },
                "filters": [
                    {
                        "type": "event",
                        "key": "detail.responseElements.virtualService.metadata.meshOwner",
                        "op": "ne",
                        "value": "detail.responseElements.virtualService.metadata.resourceOwner",
                        "value_type": "expr"

                    }
                ]

            },
            session_factory=session_factory,
        )

        # event_data() names a file in tests/data/cwe that will drive the test execution.
        # file contains an event matching that which AWS would generate in cloud trail.
        event = {
            "detail": event_data("event-appmesh-create-virtualservice.json"),
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
                  "arn":
                      "arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualService/vs1.m1.us-east-1.local",
                  "createdAt": "2023-11-03T02:36:27.877000+00:00",
                  "lastUpdatedAt": "2023-11-03T02:36:27.877000+00:00",
                  "meshOwner": "644160558196",
                  "resourceOwner": "644160558198",
                  "uid": "c5a31c64-5f82-4d39-8efd-304cd871ecf4",
                  "version": 1},
              "spec": {
                  "provider": {
                      "virtualRouter": {
                          "virtualRouterName": "vr1"
                      }
                  }
              },
              "status": {
                  "status": "ACTIVE"
              },
              "virtualServiceName": "vs1.m1.us-east-1.local"}],
            resources,
        )

        # These assertions are necessary to be sure that the "get_arns" function is
        # correctly deriving the ARN.
        # See the documentation on the "arn" field in appmesh.py.
        arns = p.resource_manager.get_arns(resources)
        self.assertEqual(
            ['arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualService/vs1.m1.us-east-1.local'],
            arns)

        # The "placebo" testing library doesn't allow us to make assertions
        # linking specific api's calls to the specific mock response file
        # that will serve that request. So we will compensate here by
        # making an assertion about all the api calls and the order
        # of calls that must be made.
        self.assertEqual(
            [
                {
                    'operation': 'DescribeVirtualService',
                    'params': {'meshName': 'm1', 'virtualServiceName': 'vs1.m1.us-east-1.local'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'GetResources',
                    'params': {
                        'ResourceARNList': [
                            'arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualService/vs1.m1.us-east-1.local'
                        ]
                    },
                    'service': 'resourcegroupstaggingapi',
                },
            ],
            captor.calls,
        )

    def test_reporting(self):
        f = Formatter(resource_type=AppmeshVirtualService.resource_type,
                      extra_fields=["mesh=meshName"])

        # provide a fake resource
        report = f.to_csv(
            records=[
                {'Tags': [{'Key': 'MODULE_NAME', 'Value': 'ecs-application'},
                          {'Key': 'ECS_APPLICATION', 'Value': 'ec1'}],
                 'c7n:MatchedFilters': ['metadata.resourceOwner'],
                 'meshName': 'm1',
                 'metadata': {
                     "arn":
                       "arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualService/vs2.m1.us-east-1.local",
                     "createdAt": "2023-11-03T02:36:27.877000+00:00",
                     "lastUpdatedAt": "2023-11-03T02:36:27.877000+00:00",
                     "meshOwner": "644160558196",
                     "resourceOwner": "644160558198",
                     "uid": "f5b0ace5-d9e7-4f16-ac9c-44c30dc0ad30",
                     "version": 1},
                 "spec": {
                     "provider": {
                         "virtualRouter": {
                             "virtualRouterName": "vr2"
                         }
                     }
                 },
                 "status": {
                     "status": "ACTIVE"
                 },
                 "virtualServiceName": "vs2.m1.us-east-1.local"}
            ],
        )

        headers = list(f.headers())

        # expect Formatter to inspect the definition of certain
        # fields ("id", "name" and "date") from the AppMesh def
        # and to pick out those fields from a fake resource
        self.assertEqual(["metadata.arn", "virtualServiceName", "metadata.createdAt", "mesh"],
                         headers, "header")

        self.assertEqual([["arn:aws:appmesh:us-east-1:644160558196:mesh/m1/virtualService/vs2.m1.us-east-1.local",
                           "vs2.m1.us-east-1.local",
                           "2023-11-03T02:36:27.877000+00:00",
                           "m1"]
                          ], report, "data")
