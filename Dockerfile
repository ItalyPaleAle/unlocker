FROM mcr.microsoft.com/cbl-mariner/distroless/minimal:2.0-nonroot
# TARGETARCH is set automatically when using BuildKit
ARG TARGETARCH
COPY .bin/linux-${TARGETARCH}/unlocker /bin
CMD ["/bin/unlocker"]
