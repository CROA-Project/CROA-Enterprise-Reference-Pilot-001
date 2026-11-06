# Q2 modelled CROA run - offline runtime image.
# Built with: docker build --pull=false --network=none -t q2-croa-run:v0.1 docker/
# Base is the locally present python:3.12-slim. No RUN steps: no apt, no pip
# (MRH is stdlib-only, dependencies = []). MRH and the fixture are NOT baked in;
# both are bind-mounted read-only at run time.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0 \
    PYTHONPATH=/opt/mrh:/opt/fixture

# Non-root, numeric uid/gid (no user creation needed, so no RUN step).
USER 10001:10001
WORKDIR /tmp
