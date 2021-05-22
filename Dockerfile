FROM gcr.io/distroless/base-debian10
# TARGETARCH is set automatically when using BuildKit
ARG TARGETARCH
RUN echo "Taret: ${TARGETARCH}"
RUN ls -al .bin
COPY .bin/${TARGETARCH}/unlocker /bin
CMD ["/bin/unlocker"]
