FROM ellinalopez/cloud-studio:latest
COPY models.json ./
COPY unified-server.js ./
COPY patch-playwright.js ./
RUN node patch-playwright.js
