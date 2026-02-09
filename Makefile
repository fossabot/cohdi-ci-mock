IMAGE_NAME := mock_cohdi
TAG := test

.PHONY: all build

all: build

build:
	docker build -t $(IMAGE_NAME):$(TAG) .
