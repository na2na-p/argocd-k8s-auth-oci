FROM golang:1.26.1-alpine AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG TARGETARCH

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /argocd-k8s-auth-oci .

FROM busybox:1.37-uclibc AS busybox

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=busybox /bin/busybox /bin/cp
COPY --from=builder /argocd-k8s-auth-oci /argocd-k8s-auth-oci

ENTRYPOINT ["/argocd-k8s-auth-oci"]
