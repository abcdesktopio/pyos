all: version

version:
	$(shell ./mkversion.sh)

flake:
	flake8 --ignore=E1,E2,E3,W1,W2,E501 .

vulture:
	vulture . --min-confidence 100 --exclude pan

.PHONY: test
PYOS_TEST_IMAGE ?= localhost:5000/ghcr.io/abcdesktopio/pyos:4.4

test:
	docker run --rm \
		-v "$(CURDIR):/var/pyos" \
		-w /var/pyos \
		--entrypoint python3 \
		$(PYOS_TEST_IMAGE) tests/run_tests.py

install:
	pip3 install -r requirements.txt --upgrade
