FROM gcr.io/distroless/base-debian11
# TARGETARCH is set automatically when using BuildKit
ARG TARGETARCH
COPY .bin/linux-${TARGETARCH}/unlocker /bin
CMD ["/bin/unlocker"]
