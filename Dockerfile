# build stage
FROM golang:1.12.6-stretch AS build-env
ADD . /src
ENV CGO_ENABLED=0
WORKDIR /src
RUN go build -o dnsmasq_exporter

# final stage
FROM scratch
WORKDIR /app
COPY --from=build-env /src/dnsmasq_exporter /app/
ENTRYPOINT ["/app/dnsmasq_exporter"]
