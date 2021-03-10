FROM alpine:latest
RUN apk add jq net-tools iproute2 util-linux
COPY --chown=0:0 default/ /
CMD ["/bin/nsm-nse-generic"]
