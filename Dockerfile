FROM python:3.12-slim-bookworm
ARG VCS_REF=unknown
LABEL org.opencontainers.image.source="https://github.com/xiaomiiraqly-alt/ai-dns-manager" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY ai_dns_manager/ /app/ai_dns_manager/
COPY config/ /app/config/
USER 65534:65534
ENTRYPOINT ["python", "-m", "ai_dns_manager"]
CMD ["--config", "config/providers.json", "--output", "-"]
