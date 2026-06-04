#!/usr/bin/env bash
set -euo pipefail

AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-YOUR_ACCOUNT_ID}"
CLUSTER_NAME="${CLUSTER_NAME:-soap-dast-lab}"
SERVICE_NAME="${SERVICE_NAME:-soap-dast-lab}"
REPOSITORY_NAME="${REPOSITORY_NAME:-soap-dast-lab}"
IMAGE_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${REPOSITORY_NAME}:latest"
SUBNETS="${SUBNETS:-subnet-REPLACE_ME,subnet-REPLACE_ME}"
SECURITY_GROUPS="${SECURITY_GROUPS:-sg-REPLACE_ME}"
PUBLIC_HOST="${PUBLIC_HOST:-REPLACE_WITH_PUBLIC_DNS_OR_LOAD_BALANCER}"

aws ecr describe-repositories --repository-names "${REPOSITORY_NAME}" --region "${AWS_REGION}" >/dev/null 2>&1 || \
  aws ecr create-repository --repository-name "${REPOSITORY_NAME}" --region "${AWS_REGION}" >/dev/null

aws ecr get-login-password --region "${AWS_REGION}" | \
  docker login --username AWS --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

docker build -t "${REPOSITORY_NAME}:latest" .
docker tag "${REPOSITORY_NAME}:latest" "${IMAGE_URI}"
docker push "${IMAGE_URI}"

aws logs create-log-group --log-group-name "/ecs/${SERVICE_NAME}" --region "${AWS_REGION}" >/dev/null 2>&1 || true
aws ecs create-cluster --cluster-name "${CLUSTER_NAME}" --region "${AWS_REGION}" >/dev/null 2>&1 || true

sed \
  -e "s|YOUR_ACCOUNT_ID|${AWS_ACCOUNT_ID}|g" \
  -e "s|YOUR_REGION|${AWS_REGION}|g" \
  -e "s|YOUR_ACCOUNT_ID.dkr.ecr.YOUR_REGION.amazonaws.com/soap-dast-lab:latest|${IMAGE_URI}|g" \
  -e "s|REPLACE_WITH_PUBLIC_DNS_OR_LOAD_BALANCER|${PUBLIC_HOST}|g" \
  deploy/aws/ecs-task-definition.json > /tmp/soap-dast-lab-task-definition.json

aws ecs register-task-definition \
  --cli-input-json file:///tmp/soap-dast-lab-task-definition.json \
  --region "${AWS_REGION}" >/dev/null

aws ecs create-service \
  --cluster "${CLUSTER_NAME}" \
  --service-name "${SERVICE_NAME}" \
  --task-definition soap-dast-lab \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[${SUBNETS}],securityGroups=[${SECURITY_GROUPS}],assignPublicIp=ENABLED}" \
  --region "${AWS_REGION}"
