# syntax=docker/dockerfile:1
#
# Two-stage build: compile the extension jar, then bake it into a Keycloak image
# so `docker compose up` yields a Keycloak with the atomic-auth-flows endpoint
# already available. No local JDK/Maven needed.

# Keycloak version for the runtime image. Declared before the first FROM so it
# can be interpolated into the stage-2 base image tag. Pin it to the version the
# extension is compiled against (pom.xml keycloak.version).
ARG KEYCLOAK_VERSION=26.5.7

# --- Stage 1: build the extension jar ----------------------------------------
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /workspace
# Resolve dependencies first so they cache across source-only changes.
COPY pom.xml .
RUN mvn -B -q dependency:go-offline || true
COPY src ./src
# Tests use Testcontainers (a Docker daemon); skip them in the image build.
RUN mvn -B -DskipTests clean package

# --- Stage 2: Keycloak with the extension loaded -----------------------------
FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}

COPY --from=build /workspace/target/keycloak-atomic-auth-flows.jar /opt/keycloak/providers/
# Minimal realm imported on startup (see docker-compose.yml `--import-realm`).
COPY examples/docker/demo-realm.json /opt/keycloak/data/import/demo-realm.json

# Bake the provider into the server image.
RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start-dev", "--import-realm"]
