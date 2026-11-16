
FROM jenkins/jenkins:lts-jdk21

USER root

# Install Docker CLI, Git, curl and certificates
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    docker.io \
    git \
    curl \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install useful Jenkins plugins
USER jenkins
