# Base image with OpenJDK 21 LTS on Ubuntu Jammy (supports linux/amd64 and linux/arm64)
FROM eclipse-temurin:21-jdk-jammy

# SDK Version argument (default to stable 3.7.1)
ARG DPM_VERSION=3.7.1

# Environment configurations
ENV DPM_HOME=/root/.dpm
ENV PATH="${DPM_HOME}/bin:/usr/local/bin:${PATH}"

# Install necessary prerequisites
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    git \
    gzip \
    make \
    tar \
    && rm -rf /var/lib/apt/lists/*

# Install dpm SDK and pre-bootstrap components
RUN curl -sSL https://get.digitalasset.com/install/install.sh | sh -s -- ${DPM_VERSION} \
    && rm -rf /root/.dpm/cache/oci-layout/*

# Create symlinks so that both 'daml' and 'dpm' commands function identically from standard PATH
RUN ln -sf "${DPM_HOME}/bin/dpm" /usr/local/bin/dpm \
    && ln -sf "${DPM_HOME}/bin/dpm" /usr/local/bin/daml

# Ensure non-root read/write/execute permissions across DPM_HOME
RUN chmod 755 /root && chmod -R a+rwX /root/.dpm

# Working directory
WORKDIR /workspace

# Default command
CMD ["daml", "version"]
