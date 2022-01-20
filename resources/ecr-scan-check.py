#!/usr/bin/env python3

import argparse
import boto3
import json
import os
import sys
import time

def logoutput(level, message):
  colours = {
    "Info": '\033[1;34m',
    "Error": '\033[0;31m',
    "Success": '\033[0;32m',
    "end": '\033[0m'
  }

  string = "{}{}:{} {}".format(colours[level], level, colours["end"], message)
  print(string)

def get_severities(min_severity):
  severities = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFORMATIONAL"
  ]

  if min_severity == "ANY":
    selected_severities = severities
  else:
    selected_severities = []
    for severity in severities:
      selected_severities.append(severity)
      if severity == min_severity:
        break

  return selected_severities

def ecr_opensession():
  logoutput("Info", "Logging in to ECR")
  try:
    session = boto3.Session(
      aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
      aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
      region_name=os.environ.get("AWS_REGION"),
    )
    ecr_client = session.client('ecr')

  except session.exceptions.UnauthorizedException as err:
    logoutput("Error", "Unable to authorise request. Invalid credentials")
    sys.exit(1)

  return ecr_client

def ecr_describescanfindings(ecr_client, imagerepo, imagetag):
  logoutput("Info", "Getting scan results...")
  try:
    response = ecr_client.describe_image_scan_findings(
      repositoryName=imagerepo,
      imageId={
        'imageTag': imagetag,
      },
    )

    logoutput("Info", "Image digest: {}".format(response["imageId"]["imageDigest"]))

  except ecr_client.exceptions.ImageNotFoundException as err:
    logoutput("Error", "No results found for image " + imagerepo + " with tag " + imagetag)
    sys.exit(1)

  except ecr_client.exceptions.RepositoryNotFoundException as err:
    logoutput("Error", "No repository found with name " + imagerepo)
    sys.exit(1)

  return response


def parse_scanresults(response, severities):
  logoutput("Info", "Severities included: " + ','.join(severities))
  vulnerabilities = False
  if len(response["imageScanFindings"]["findingSeverityCounts"]) > 0:
    for severity in response["imageScanFindings"]["findingSeverityCounts"]:
      if severity in severities:
        vulnerabilities = True
        count = response["imageScanFindings"]["findingSeverityCounts"][severity]
        logoutput("Error", "{}: {}".format(severity, count))

  return vulnerabilities


def generate_reporturl(ecr_scanfindings, region):
  report_url = "https://{region}.console.aws.amazon.com/ecr/repositories/private/{registry}/{repository}/image/{digest}/scan-results/?region={region}".format(
    region = region,
    registry = ecr_scanfindings["registryId"],
    repository = ecr_scanfindings["repositoryName"],
    digest = ecr_scanfindings["imageId"]["imageDigest"]
  )

  return report_url


def generate_slackjson(ecr_imagedata, vulnerabilities, report_url, report_dir):
  if vulnerabilities:
    colour = "#FF0000"
    heading = "ECR vulnerability scan failure"
    result = "Vulnerabilities found"
  else:
    colour = "#00FF00"
    heading = "Successful ECR vulnerability scan"
    result = "No vulnerabilities"

  image_name = ecr_imagedata["repositoryName"]
  image_tag = ecr_imagedata["imageId"]["imageTag"]

  slack_json = [
  {
    "fallback": heading,
    "pretext": heading +" for *<$ATC_EXTERNAL_URL/teams/$BUILD_TEAM_NAME/pipelines/$BUILD_PIPELINE_NAME/jobs/$BUILD_JOB_NAME/builds/$BUILD_NAME|$BUILD_PIPELINE_NAME>*",
    "fields": [
        {
            "title": "Image Name",
            "value": image_name,
            "short": "true"
        },
        {
            "title": "Image Tag",
            "value": image_tag,
            "short": "true"
        },
        {
            "title": "Scan Result:",
            "value": "<"+ report_url +"|"+ result +">",
            "short": "false"
        }
    ],
    "color": colour,
    "footer": "$ATC_EXTERNAL_URL"
  }
]

  if not os.path.exists(report_dir):
    os.mkdir(report_dir)

  json_path = "./" + report_dir + "/report.json"
  with open(json_path, 'w', encoding='utf-8') as result_file:
    json.dump(slack_json, result_file, ensure_ascii=False, indent=4)

  result_file.close()


if __name__ == "__main__":
  # Ensure required environment vars are set
  if not os.environ.get("AWS_ACCESS_KEY_ID") or not os.environ.get("AWS_SECRET_ACCESS_KEY") or not os.environ.get("AWS_REGION"):
    logoutput("Error", "Required AWS environment variables missing or not set")
    sys.exit(1)

  # Parse command line arguments/options
  parser = argparse.ArgumentParser(description="Program arguments and options")
  parser.add_argument("imagerepo", help="Image repository name")
  parser.add_argument("imagetag", help="Image tag to filter for")
  args = parser.parse_args()

  # Determine which severity of vulnerabilities we care about
  if os.environ.get("MIN_SEVERITY"):
    severities = get_severities(os.environ.get("MIN_SEVERITY"))
  else:
    severities = get_severities("ANY")

  # Set the report output directory
  if os.environ.get("REPORT_DIR"):
    report_dir = os.environ.get("REPORT_DIR")
  else:
    report_dir = "scan-report"

  logoutput("Info", "Image name: " + args.imagerepo + ", Tag: " + args.imagetag)

  # Initialise the boto3 session and return an ECR client
  ecr_client = ecr_opensession()

  # Query the ECR API to return the image scan findings
  ecr_imagedata = ecr_describescanfindings(ecr_client, args.imagerepo, args.imagetag)

  # Wait and try again if the scan status is not COMPLETE
  while ecr_imagedata["imageScanStatus"]["status"] != "COMPLETE":
    logoutput("Info", "Waiting for image scan to complete...")
    time.sleep(5)
    ecr_imagedata = ecr_describescanfindings(ecr_client, args.imagerepo, args.imagetag)

  logoutput("Info", "Scan status: {}".format(ecr_imagedata["imageScanStatus"]["status"]))

  # Parse the scan results for the appropriate severities
  vulnerabilities = parse_scanresults(ecr_imagedata, severities)

  # Build the URL to view the scan report
  report_url = generate_reporturl(ecr_imagedata, os.environ.get("AWS_REGION"))

  # Build and output the JSON for the Slack message
  generate_slackjson(ecr_imagedata, vulnerabilities, report_url, report_dir)

  if vulnerabilities:
    logoutput("Error", "Vulnerabilities found.")
    sys.exit(1)
  else:
    # No vulnerabilities found, exit cleanly
    logoutput("Success", "No vulnerabilities found.")
    sys.exit(0)
