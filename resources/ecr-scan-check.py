#!/usr/bin/env python3

import argparse
import botocore
import boto3
import json
import os
import sys
import time

severities = [
    'INFORMATIONAL',
    'LOW',
    'MEDIUM',
    'HIGH',
    'CRITICAL',
]

def log_output(level, message):
    colours = {
        "Info": "\033[1;34m",
        "Error": "\033[0;31m",
        "Success": "\033[0;32m",
        "end": "\033[0m",
    }

    string = "{}{}:{} {}".format(colours[level], level, colours["end"], message)
    print(string)

def check_environment_variables():
    required_vars = [
        'AWS_ACCESS_KEY_ID',
        'AWS_SECRET_ACCESS_KEY',
        'AWS_REGION',
    ]

    missing_vars = []
    for env_var in required_vars:
        if os.getenv(env_var) is None:
            missing_vars.append(env_var)

    if missing_vars:
        log_output("Error", f"Mandatory environment variable(s) undefined: {', '.join(missing_vars)}")
        sys.exit(1)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Program arguments and options")
    parser.add_argument("imagerepo", help="Image repository name")
    parser.add_argument("imagetag", help="Image tag to filter for")

    return parser.parse_args()

def get_severities(level):
    if level is None:
        return severities
    else:
        return severities[severities.index(level):]

def ecr_open_session():
    log_output("Info", "Opening AWS session...")
    try:
        session = boto3.Session(
            aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
            region_name=os.environ.get("AWS_REGION"),
        )
        ecr_client = session.client("ecr")

    except session.exceptions.UnauthorizedException as err:
        logoutput("Error", "Invalid SSO credentials")
        sys.exit(1)

    return ecr_client


def ecr_describe_scan_findings(ecr_client, imagerepo, imagetag):
    log_output("Info", "Querying ECR for scan results...")
    try:
        response = ecr_client.describe_image_scan_findings(
            repositoryName=imagerepo,
            imageId={
                "imageTag": imagetag,
            },
        )

        log_output("Info", "Image digest: {}".format(response["imageId"]["imageDigest"]))

    except botocore.exceptions.ClientError as err:
        if err.response['Error']['Code'] == 'UnrecognizedClientException':
            log_output("Error", "Unable to authenticate with provided credentials")
            sys.exit(1)

        elif err.response['Error']['Code'] == 'ImageNotFoundException':
            log_output("Error", "No results found for image " + imagerepo + " with tag " + imagetag)
            sys.exit(1)

        elif err.response['Error']['Code'] == 'RepositoryNotFoundException':
            log_output("Error", "No repository found with name " + imagerepo)
            sys.exit(1)

        else:
            log_output("Error", err)
            sys.exit(1)

    return response


def parse_scan_results(response, severities):
    log_output("Info", "Severities included: " + ",".join(severities))
    vulnerabilities = False
    if len(response["imageScanFindings"]["findingSeverityCounts"]) > 0:
        for severity in response["imageScanFindings"]["findingSeverityCounts"]:
            if severity in severities:
                vulnerabilities = True
                count = response["imageScanFindings"]["findingSeverityCounts"][severity]
                log_output("Error", "{}: {}".format(severity, count))

    return vulnerabilities


def generate_report_url(ecr_scanfindings, region):
    report_url = "https://{region}.console.aws.amazon.com/ecr/repositories/private/{registry}/{repository}/image/{digest}/scan-results/?region={region}".format(
        region=region,
        registry=ecr_scanfindings["registryId"],
        repository=ecr_scanfindings["repositoryName"],
        digest=ecr_scanfindings["imageId"]["imageDigest"],
    )

    return report_url


def generate_slack_json(ecr_imagedata, vulnerabilities, report_url, image_name, image_tag):
    if vulnerabilities:
        colour = "#FF0000"
        heading = "ECR vulnerability scan failure"
        result = "Vulnerabilities found"
    else:
        colour = "#00FF00"
        heading = "Successful ECR vulnerability scan"
        result = "No vulnerabilities"

    slack_json = [
        {
            "fallback": heading,
            "pretext": heading
            + " for *<$ATC_EXTERNAL_URL/teams/$BUILD_TEAM_NAME/pipelines/$BUILD_PIPELINE_NAME/jobs/$BUILD_JOB_NAME/builds/$BUILD_NAME|$BUILD_PIPELINE_NAME>*",
            "fields": [
                {"title": "Image Name", "value": image_name, "short": "true"},
                {"title": "Image Tag", "value": image_tag, "short": "true"},
                {
                    "title": "Scan Result:",
                    "value": "<" + report_url + "|" + result + ">",
                    "short": "false",
                },
            ],
            "color": colour,
            "footer": "$ATC_EXTERNAL_URL",
        }
    ]

    report_dir = "scan-report"
    if not os.path.exists(report_dir):
        os.mkdir(report_dir)

    json_path = f"./{report_dir}/report.json"
    with open(json_path, "w", encoding="utf-8") as result_file:
        json.dump(slack_json, result_file, ensure_ascii=False, indent=4)

    result_file.close()


if __name__ == "__main__":
    # Ensure required environment vars are set
    check_environment_variables()

    # Parse command line arguments/options
    args = parse_arguments()

    # Determine which severity of vulnerabilities we care about
    if os.environ.get("MIN_SEVERITY"):
        severities = get_severities(os.environ.get("MIN_SEVERITY"))
    else:
        severities = get_severities(None)

    log_output("Info", "Image name: " + args.imagerepo + ", Tag: " + args.imagetag)

    # Initialise the boto3 session and return an ECR client
    ecr_client = ecr_open_session()

    # Query the ECR API to return the image scan findings
    ecr_imagedata = ecr_describe_scan_findings(ecr_client, args.imagerepo, args.imagetag)

    # Wait and try again if the scan status is not COMPLETE
    # Loop for loop_max_wait seconds before exiting
    if os.environ.get("MAX_WAIT"):
        loop_max_wait = int(os.environ.get("MAX_WAIT"))
    else:
        loop_max_wait = 120
    log_output("Info", "Scan check timeout: {} seconds".format(loop_max_wait))

    loop_timeout = time.time() + loop_max_wait
    while ecr_imagedata["imageScanStatus"]["status"] != "COMPLETE":
        log_output("Info", "Waiting for image scan to complete...")
        time.sleep(5)
        ecr_imagedata = ecr_describe_scan_findings(
            ecr_client, args.imagerepo, args.imagetag
        )
        if time.time() > loop_timeout:
            log_output("Error", "Timed-out waiting for image scan to complete.")
            sys.exit(1)

    log_output(
        "Info", "Scan status: {}".format(ecr_imagedata["imageScanStatus"]["status"])
    )

    # Parse the scan results for the appropriate severities
    vulnerabilities = parse_scan_results(ecr_imagedata, severities)

    # Build the URL to view the scan report
    report_url = generate_report_url(ecr_imagedata, os.environ.get("AWS_REGION"))

    # Build and output the JSON for the Slack message
    generate_slack_json(ecr_imagedata, vulnerabilities, report_url, args.imagerepo, args.imagetag)

    if vulnerabilities:
        log_output("Error", "Vulnerabilities found.")
        sys.exit(1)
    else:
        # No vulnerabilities found, exit cleanly
        log_output("Success", "No vulnerabilities found.")
        sys.exit(0)
