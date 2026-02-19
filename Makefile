APP=backend
BINARY=$(APP)
SRC=$(shell ls -1 | tr '\n' ' ')
 
.PHONY: build run test docker-build deploy

build:
	@echo "Building $(BINARY)";
	
run:
	@echo "Running $(BINARY)";

docker-build:
	@echo "Building docker image locally";
	@docker build -t orienteering-game-backend -f Dockerfile .

deploy:
	@echo "Deploying to Fly.io";
	@fly deploy

test:
	@echo "Running tests";
	@go test ./...
