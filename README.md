# ci-ecr-scan-check

Resources to build a container used to check the vulnerability scan status of an ECR-based container image.
Following a scan, a JSON-formatted template is written to disk that can be used to communicate the result via Slack when used in a suitable pipeline.

## Environment Variables

The script utilises the following environment variables.

| Variable Name         | Required | Default       | Description                                                                 |
| --------------------- | -------- | ------------- | --------------------------------------------------------------------------- |
| AWS_ACCESS_KEY_ID     | Yes      | -             | AWS auth access key ID                                                      |
| AWS_SECRET_ACCESS_KEY | Yes      | -             | AWS auth secret access key                                                  |
| AWS_REGION            | Yes      | -             | AWS region to connect to                                                    |
| MIN_SEVERITY          | No       | `ALL`         | Sets the minimum vulnerability severity level to indicate a failure         |
| MAX_WAIT              | No       | `120`         | Sets how long, in seconds, to wait for ECR scan results to become available |
| SLACK_CHANNEL         | Yes      | -             | Slack channel to send scan reports to. If not set, reports will be disabled |
| SLACK_WEBHOOK         | Yes      | -             | Slack webhook URL used to send the scan report                              |

## Parameters

The script requires the following positional parameters to passed.

| Parameter      | Description                                              |
| -------------- | -------------------------------------------------------- |
| `<image_name>` | The name of the container image to query the ECR API for |
| `<image_tag>`  | The specific image tag to filter the query               |

## Usage Examples

Basic usage
`docker run --rm <repository>/ci-ecr-scan-check:latest ecr-scan-check.py <image_name> <image_tag>`

Defining the minimum severity
`docker run --rm -e MIN_SEVERITY=HIGH <repository>/ci-ecr-scan-check:latest ecr-scan-check.py <image_name> <image_tag>`

Defining the maximum wait time
`docker run --rm -e MAX_WAIT=300 <repository>/ci-ecr-scan-check:latest ecr-scan-check.py <image_name> <image_tag>`

Use in a pipeline
```
- name: my-image-scan
  plan:
  - task: get-vulnerability-scan
    config:
      platform: linux
      image_resource:
        type: docker-image
        source:
          aws_access_key_id: ((aws-access-key-id))
          aws_secret_access_key: ((aws-secret-access-key))
          repository: ((repository))/ci-ecr-scan-check
          tag: latest

      outputs:
        - name: scan-report

      params:
        AWS_ACCESS_KEY_ID: ((aws-access-key-id))
        AWS_SECRET_ACCESS_KEY: ((aws-secret-access-key))
        AWS_REGION: eu-west-2
        IMAGE_NAME: <image_name>
        IMAGE_TAG: <image_tag>
        SLACK_CHANNEL: <slack_channel>

      run:
        path: bash
        args:
        - -ec
        - |
          ecr-scan-check.py ${IMAGE_NAME} ${IMAGE_TAG}

```

With Slack-based reporting of scan results disabled
```
- name: my-image-scan
  plan:
  - task: get-vulnerability-scan
    config:
      platform: linux
      image_resource:
        type: docker-image
        source:
          aws_access_key_id: ((aws-access-key-id))
          aws_secret_access_key: ((aws-secret-access-key))
          repository: ((repository))/ci-ecr-scan-check
          tag: latest

      outputs:
        - name: scan-report

      params:
        AWS_ACCESS_KEY_ID: ((aws-access-key-id))
        AWS_SECRET_ACCESS_KEY: ((aws-secret-access-key))
        AWS_REGION: eu-west-2
        IMAGE_NAME: <image_name>
        IMAGE_TAG: <image_tag>

      run:
        path: bash
        args:
        - -ec
        - |
          ecr-scan-check.py ${IMAGE_NAME} ${IMAGE_TAG}

```
