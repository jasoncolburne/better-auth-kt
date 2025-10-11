.PHONY: setup test type-check lint format format-check clean test-integration build

JAVA_HOME ?= /opt/homebrew/opt/openjdk@21

setup:
	env JAVA_HOME=$(JAVA_HOME) ./gradlew build --refresh-dependencies

test:
	env JAVA_HOME=$(JAVA_HOME) ./gradlew test

type-check:
	env JAVA_HOME=$(JAVA_HOME) ./gradlew compileKotlin compileTestKotlin

lint:
	env JAVA_HOME=$(JAVA_HOME) ./gradlew ktlintCheck

format:
	env JAVA_HOME=$(JAVA_HOME) ./gradlew ktlintFormat

format-check:
	env JAVA_HOME=$(JAVA_HOME) ./gradlew ktlintCheck

test-integration:
	env JAVA_HOME=$(JAVA_HOME) ./gradlew test --tests "com.betterauth.IntegrationTest" --rerun-tasks

build:
	env JAVA_HOME=$(JAVA_HOME) ./gradlew build

clean:
	env JAVA_HOME=$(JAVA_HOME) ./gradlew clean
	rm -rf build .gradle
