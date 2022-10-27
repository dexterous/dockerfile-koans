FROM ubuntu:22.10
LABEL MAINTAINER "Student"
WORKDIR /app

COPY app /app
COPY README.md /app/README.md
COPY code /tmp/code
RUN apt-get update
RUN apt-get install -y htop

USER app-user
CMD [".venv/bin/uvicorn", "api.main:api", "--host", "0.0.0.0", "--port", "8000"]
ENTRYPOINT ["docker-entrypoint.sh"]