ARG BUILDER_IMAGE=golang:1.21-bullseye
ARG BASE_IMAGE=alpine:3.17

FROM ${BUILDER_IMAGE} AS build-stage

ENV CGO_ENABLED=0

WORKDIR /src/

ARG FALCO_SRC_PATH

COPY $FALCO_SRC_PATH .

RUN make falcosidekick

# Final Docker image
FROM ${BASE_IMAGE} AS final-stage
LABEL MAINTAINER "Idriss Neumann <idriss.neumann@comwork.io>"

RUN apk add --update --no-cache ca-certificates curl

# Create user falcosidekick
RUN addgroup -S falcosidekick && adduser -u 1234 -S falcosidekick -G falcosidekick
# must be numeric to work with Pod Security Policies:
# https://kubernetes.io/docs/concepts/policy/pod-security-policy/#users-and-groups
USER 1234

WORKDIR ${HOME}/app

ARG FALCO_SRC_PATH

COPY $FALCO_SRC_PATH/LICENSE .

COPY --from=build-stage /src/falcosidekick .

EXPOSE 2801

ENTRYPOINT ["./falcosidekick"]
