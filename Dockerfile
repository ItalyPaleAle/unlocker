FROM gcr.io/distroless/base-debian10
# TARGETARCH is set automatically when using BuildKit
ARG TARGETARCH
COPY .bin/${TARGETARCH}/unlocker /bin
CMD ["/bin/unlocker"]
