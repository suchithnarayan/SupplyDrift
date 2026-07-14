.PHONY: install-tools deps

# SHADOW: curl download in Makefile (HIGH)
install-tools:
	curl -Lo /usr/local/bin/kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
	chmod +x /usr/local/bin/kind
	curl -fsSL https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv5.1.1/kustomize_v5.1.1_linux_amd64.tar.gz | tar xz -C /usr/local/bin/

# SHADOW: npm global install (HIGH)
deps:
	npm install -g typescript@5 prettier@3

# SHADOW: go install (MEDIUM)
go-tools:
	go install github.com/golang/mock/mockgen@v1.6.0
	go install golang.org/x/tools/cmd/goimports@latest

# SAFE: local target
build:
	go build ./...
