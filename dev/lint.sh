#!/bin/bash
ruff ../src
flake8 ../src
mypy ../src 