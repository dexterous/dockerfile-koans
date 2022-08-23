FROM ubuntu:latest as builder
LABEL MAINTAINER "Student"
WORKDIR /app

ADD app /app
COPY README.md /app/README.md
ADD code /tmp/code
RUN sudo apt-get udpate
RUN apt-get update && apt-get install -y htop
RUN apk upgrade

USER root
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 CMD [ "executable" ]
CMD [".venv/bin/uvicorn", "api.main:api", "--host", "127.0.0.1", "--port", "8000"]
ENTRYPOINT ["docker-entrypoint.sh"]

