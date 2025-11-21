# Dockerfile for a static website served with nginx
FROM nginx:stable-alpine

# [Security] Create a dedicated, non-root user.
RUN addgroup --system webgroup && \
    adduser --system --ingroup webgroup webuser

# [Permissions] Give the non-root user ownership of Nginx directories.
RUN chown -R webuser:webgroup /var/cache/nginx /var/log/nginx /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && \
    chown -R webuser:webgroup /var/run/nginx.pid

# [Configuration] Switch to the non-root user.
USER webuser

# [Content] Copy website files
COPY --chown=webuser:webgroup . /usr/share/nginx/html

# [Runtime] Expose Port 80
EXPOSE 80

# [Healthcheck]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost/ || exit 1

# [Best Practice] Graceful shutdown signal
STOPSIGNAL SIGQUIT
