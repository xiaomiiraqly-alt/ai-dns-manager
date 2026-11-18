FROM python:3.12-slim-bookworm
ARG VCS_REF=unknown
LABEL org.opencontainers.image.source="https://github.com/xiaomiiraqly-alt/ai-dns-manager" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.licenses="MIT AND Apache-2.0"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY ai_dns_manager/ /app/ai_dns_manager/
COPY config/ /app/config/
COPY third_party/ /app/third_party/
COPY LICENSE /app/LICENSE
# Docker COPY retains restrictive source permissions (e.g. git checkout
# under umask 077). Build artifacts must be readable by the non-root runtime
# regardless of the build host's umask. Do not widen permissions of any
# mounted secret file or persisted state directory: these are NOT copied.
RUN chmod -R a+rX /app/ai_dns_manager /app/config /app/third_party \
    && chmod a+r /app/LICENSE
USER 65534:65534
ENTRYPOINT ["python", "-m", "ai_dns_manager"]
CMD ["--config", "config/providers.json", "--output", "-"]
