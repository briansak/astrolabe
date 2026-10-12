# syntax=docker/dockerfile:1

FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7

COPY --from=ghcr.io/astral-sh/uv:0.9.7@sha256:ba4857bf2a068e9bc0e64eed8563b065908a4cd6bfb66b531a9c424c8e25e142 /uv /uvx /usr/local/bin/
ENV UV_BREAK_SYSTEM_PACKAGES=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates=20250419~deb12u1 \
        coreutils=9.1-1 \
        diffutils=1:3.8-4 \
        file=1:5.44-3 \
        findutils=4.9.0-4 \
        grep=3.8-5 \
        ripgrep=13.0.0-4+b2 \
        sed=4.9-1+deb12u1 \
        socat=1.7.4.4-2 \
        tree=2.1.0-1 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin antares

COPY antares-cli.zip constraints.txt /tmp/
RUN mkdir -p /opt/antares-cli \
    && python -c "import zipfile; zipfile.ZipFile('/tmp/antares-cli.zip').extractall('/opt/antares-cli')" \
    && uv pip install --system --no-cache --constraint /tmp/constraints.txt /opt/antares-cli \
    && rm -rf /opt/antares-cli /tmp/antares-cli.zip /tmp/constraints.txt

COPY long_completion.py /opt/astrolabe/long_completion.py
COPY entrypoint.sh /opt/astrolabe/entrypoint.sh
RUN chmod 755 /opt/astrolabe/entrypoint.sh /opt/astrolabe/long_completion.py \
    && mkdir -p /run/astrolabe /workspace/repo

USER antares
WORKDIR /workspace/repo
ENTRYPOINT ["/opt/astrolabe/entrypoint.sh"]
CMD ["antares", "--help"]
