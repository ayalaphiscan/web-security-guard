# Node 22.23.4: le correzioni di sicurezza del 21 ottobre 2026 (Node 20 è fuori supporto).
# Aggiornare il tag a ogni rilascio di sicurezza (Dependabot "docker" lo propone da solo).
FROM node:22.23.4-alpine
WORKDIR /app
# Dipendenze esattamente come nel lockfile: build riproducibili, niente versioni a sorpresa.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY . .
# Utente non-root: se lo scudo fosse compromesso, l'attaccante non è amministratore
RUN addgroup -S app && adduser -S app -G app && mkdir -p /app/logs && chown -R app:app /app
USER app
EXPOSE 8080
CMD ["node", "server.js"]
