# Use the same verified distribution for all build entry points.
.PHONY: all build quick full clean help test verify install compile deps info release dev
ARTIFACT := $(shell python3 scripts/verify_distribution.py --pom-property artifactId)
VERSION := $(shell python3 scripts/verify_distribution.py --pom-property version)
REVISION := $(shell python3 scripts/verify_distribution.py --pom-property uce.revision)
JAR := target/$(ARTIFACT)-$(VERSION).jar

all: build
build quick full:
	@./build.sh

clean:
	@mvn clean -q
	@rm -f dependency-reduced-pom.xml

verify:
	@python3 scripts/verify_distribution.py --jar "$(JAR)" --expected-revision "$(REVISION)" --crypto-classpath target/test-classes

test:
	@mvn test -q
compile:
	@mvn compile -q
deps:
	@mvn dependency:resolve -q

info:
	@python3 scripts/verify_distribution.py --jar "$(JAR)"

# Burp registers extensions through its UI, not by copying to a guessed directory.
install: verify
	@echo "Load $(abspath $(JAR)) in Burp: Extensions -> Installed -> Add -> Java."

# build.sh already performs a clean build; avoid parallel clean/build prerequisites.
release: build
	@python3 scripts/sync_skill.py --check
	@python3 scripts/package_release.py

dev:
	@if command -v fswatch >/dev/null 2>&1; then \
		fswatch -o src/ | xargs -n1 -I{} make build; \
	elif command -v inotifywait >/dev/null 2>&1; then \
		while inotifywait -e modify -r src/; do make build; done; \
	else echo "Install fswatch or inotify-tools for file watching."; exit 1; fi

help:
	@echo "make build/quick/full: clean verify, signed BC and final JAR crypto checks"
	@echo "make verify: verify the built JAR; failures return a nonzero exit code"
	@echo "make test/compile/deps/clean: Maven development operations"
	@echo "make install: show the verified JAR path for manual Burp registration"
	@echo "make release: build, check Skill consistency and create a portable ZIP"
