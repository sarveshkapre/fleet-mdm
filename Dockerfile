FROM python:3.12-slim

WORKDIR /app

RUN useradd -m fleet

COPY pyproject.toml README.md LICENSE /app/
COPY src /app/src

RUN pip install --no-cache-dir -U pip \
    && pip install --no-cache-dir -e .

USER fleet

ENTRYPOINT ["fleetmdm"]
CMD ["--help"]
