all: version

version:
	$(shell ./mkversion.sh)

flake:
	flake8 --ignore=E1,E2,E3,W1,W2,E501 .

vulture:
	vulture . --min-confidence 100 --exclude pan

install:
	pip3 install -r requirements.txt --upgrade

# Trivy image scan
# Usage: make trivy-scan IMAGE=myrepo/myimage:tag
# Or set a default image: make trivy-scan
TRIVY_IMAGE ?= abcdesktopio/pyos:latest
TRIVY_SEVERITY ?= UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL
TRIVY_OUTPUT ?= table
TRIVY_EXIT_CODE ?= 1

trivy-scan:
	trivy image \
		--severity $(TRIVY_SEVERITY) \
		--format $(TRIVY_OUTPUT) \
		--exit-code $(TRIVY_EXIT_CODE) \
		$(if $(IMAGE),$(IMAGE),$(TRIVY_IMAGE))

trivy-scan-json:
	trivy image \
		--severity $(TRIVY_SEVERITY) \
		--format json \
		--output trivy-report.json \
		--exit-code $(TRIVY_EXIT_CODE) \
		$(if $(IMAGE),$(IMAGE),$(TRIVY_IMAGE))

trivy-scan-sarif:
	trivy image \
		--severity $(TRIVY_SEVERITY) \
		--format sarif \
		--output trivy-report.sarif \
		--exit-code $(TRIVY_EXIT_CODE) \
		$(if $(IMAGE),$(IMAGE),$(TRIVY_IMAGE))

.PHONY: trivy-scan trivy-scan-json trivy-scan-sarif
