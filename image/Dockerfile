FROM golang:1.16 as build
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOBIN=/bin
WORKDIR /app
RUN go get github.com/grpc-ecosystem/grpc-health-probe@v0.4.2

FROM alpine:latest
RUN apk add jq net-tools iproute2 util-linux
COPY --chown=0:0 default/ /
COPY --from=build /bin/grpc-health-probe /bin/grpc_health_probe
CMD ["/bin/nsm-nse-generic"]
