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
USER 65534:65534
ENTRYPOINT ["python", "-m", "ai_dns_manager"]
CMD ["--config", "config/providers.json", "--output", "-"]
