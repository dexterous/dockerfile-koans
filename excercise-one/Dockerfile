FROM ubuntu:latest as builder
LABEL MAINTAINER "Student"
WORKDIR /app

ADD app /app
COPY README.md /app/README.md
ADD code /tmp/code
RUN sudo apt-get update
RUN apt-get install -y htop
RUN apt-get upgrade

USER root
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 CMD [ "executable" ]
CMD [".venv/bin/uvicorn", "api.main:api", "--host", "127.0.0.1", "--port", "8000"]
ENTRYPOINT ["docker-entrypoint.sh"]

