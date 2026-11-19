# Multi-stage build: compile in 'build', ship only the artifact.
FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod go.sum /src/
RUN go build -o /out/app ./...
COPY . /src
RUN go build -o /out/app ./...

FROM gcr.io/distroless/static
COPY --from=build /out/app /app
USER 65532
ENTRYPOINT ["/app"]
