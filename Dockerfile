# build stage
FROM golang:1.17.2-stretch AS build-env
ADD . /src
ENV CGO_ENABLED=0
WORKDIR /src
RUN go build -o dnsmasq_exporter

# final stage
FROM scratch
WORKDIR /app
COPY --from=build-env /src/dnsmasq_exporter /app/
USER 65534
ENTRYPOINT ["/app/dnsmasq_exporter"]
