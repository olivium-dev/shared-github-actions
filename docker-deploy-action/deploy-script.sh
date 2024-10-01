#!/bin/bash

echo "Setting up SSH key for deployment..."
mkdir -p ~/.ssh
echo "${SERVER_SSH_PRIVATE_KEY}" | base64 --decode > ~/.ssh/id_rsa
chmod 600 ~/.ssh/id_rsa
ssh-keyscan -H ${SERVER_HOST} >> ~/.ssh/known_hosts

echo "Logging into Docker registry..."
echo ${GITHUB_TOKEN} | docker login ${REGISTRY} -u ${GITHUB_ACTOR} --password-stdin

echo "Pulling Docker image..."
docker pull ${REGISTRY}/${IMAGE_NAME}:${GITHUB_RUN_ID}

echo "Removing old Docker service if it exists..."
ssh -i ~/.ssh/id_rsa ${SERVER_USER}@${SERVER_HOST} \
  "docker service rm ${SERVICE_NAME} || echo 'Service not found. Removing any old services.'"

echo "Deploying Docker image as a service..."
ssh -i ~/.ssh/id_rsa ${SERVER_USER}@${SERVER_HOST} \
  "docker service create --name ${SERVICE_NAME} --network my-network --publish published=${EXTERNAL_PORT},target=${INTERNAL_PORT} --replicas 1 --restart-condition any ${REGISTRY}/${IMAGE_NAME}:${GITHUB_RUN_ID}"
