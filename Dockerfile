FROM python:3.12-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -e .

ENV PERSONASHIELD_HOME=/data
VOLUME ["/data"]

ENTRYPOINT ["personashield"]
CMD ["--help"]
