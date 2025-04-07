FROM python:alpine3.14

ARG artifacts_dir

COPY $artifacts_dir /artifacts
