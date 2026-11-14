FROM node:26.13.1@sha256:e18c3ccdf7d71619990b0e85639f506e2028a95410999cab24cc373cbd10e0ac AS frontend
WORKDIR /source
COPY web/ /source/web/
RUN npm --prefix web ci && npm --prefix web run build

FROM golang:1.27.4@sha256:5e8afd493a7124a8586e134d9b532731161d4b9becf9dee5a5956b107426f93d AS build
WORKDIR /source
ENV GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY --from=frontend /source/internal/console/static/ ./internal/console/static/
RUN go build -mod=readonly -trimpath -buildvcs=false -o /memberid ./cmd/memberid

FROM scratch
COPY --from=build /memberid /usr/local/bin/memberid
COPY third_party/ /usr/share/memberid/third_party/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/memberid"]
