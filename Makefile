VERMIN_FILES=vermin.py `find vermin -iname '*.py'`
TEST_FILES=runtests.py `find tests -iname '*.py'`
OTHER_FILES=count.py
ALL_FILES=${VERMIN_FILES} ${TEST_FILES} ${OTHER_FILES}
MODULES=vermin tests

self-test:
	./vermin.py -v -t=2.7 -t=3 ${VERMIN_FILES}

test: self-test
	./runtests.py

test-all:
	python2.7 ./runtests.py
	python3 ./runtests.py

count:
	./count.py
	@echo "Tests: `grep -ri 'def test_' tests | wc -l | xargs` (\
`find tests -iname '*.py' | xargs cat | grep -iE 'self\..*assert.*?\(' |\
wc -l | xargs` assertions)"
	@echo "Vermin SLOC: `sloccount vermin/ vermin.py 2>/dev/null | grep 'python:' | xargs`"
	@echo "Tests  SLOC: `sloccount tests/ runtests.py 2>/dev/null | grep 'python:' | xargs`"

setup-venv: clean-venv
	virtualenv -p python3 .venv

setup-misc: clean
	.venv/bin/pip install -r misc/.misc-requirements.txt

setup-coverage: clean
	.venv/bin/pip install -r misc/.coverage-requirements.txt

setup-bandit: clean
	.venv/bin/pip install -r misc/.bandit-requirements.txt

setup: setup-venv setup-misc setup-coverage setup-bandit

setup-misc-3.5: clean
	.venv/bin/pip install -r misc/.misc-requirements.3_5.txt

setup-coverage-3.5: clean
	.venv/bin/pip install -r misc/.coverage-requirements.3_5.txt

setup-bandit-3.5: clean
	.venv/bin/pip install -r misc/.bandit-requirements.3_5.txt

setup-3.5: setup-venv setup-misc-3.5 setup-coverage-3.5 setup-bandit-3.5

clean:
	find . -iname __pycache__ | xargs rm -fr
	find . -iname '*.pyc' | xargs rm -f

clean-venv:
	rm -fr .venv

clean-pypi:
	rm -fr build dist *.egg-info

dist-clean: clean clean-venv clean-pypi

pypi-dist: clean-pypi
	python setup.py bdist_wheel --universal

update-misc-requirements: setup-venv setup-misc
	.venv/bin/pip freeze > misc/.misc-requirements.txt

update-coverage-requirements: setup-venv setup-coverage
	.venv/bin/pip freeze > misc/.coverage-requirements.txt

update-bandit-requirements: setup-venv setup-bandit
	.venv/bin/pip freeze > misc/.bandit-requirements.txt

check-style:
	.venv/bin/flake8 --ignore E111,E114,E121,E126,E127,E302,E305,W504,F821\
          --max-line-length 100 --count --show-source ${ALL_FILES}

static-analysis:
	.venv/bin/vulture --min-confidence 70 --sort-by-size ${ALL_FILES}

check-unused:
	.venv/bin/vulture --sort-by-size ${VERMIN_FILES}

security-check:
	.venv/bin/bandit -r -s B101 ${MODULES}

check: check-style static-analysis

# NOTE: `check` doesn't check all because bandit doesn't run on py37+ yet.
check-all: check security-check

test-coverage:
	.venv/bin/coverage run --source=vermin,tests runtests.py
	.venv/bin/coverage run --append --source=vermin ./vermin.py -v -t=2.7 -t=3 ${VERMIN_FILES}

coveralls:
	COVERALLS_REPO_TOKEN=twBSHlgE5AMFEQNmUK04LDcN7SVth3lDV .venv/bin/coveralls
