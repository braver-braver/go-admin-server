FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server && mkdir -p /out/data/uploads

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/server /server
# Owned by the nonroot user so a fresh volume mounted here is writable.
COPY --from=build --chown=65532:65532 /out/data /data
ENV LISTEN_ADDR=:8080 UPLOAD_DIR=/data/uploads
EXPOSE 8080
ENTRYPOINT ["/server"]
