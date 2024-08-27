# Utilizziamo l'immagine ufficiale di Go per la fase di build
FROM golang:1.20 AS builder

# Impostiamo la directory di lavoro
WORKDIR /app

# Copiamo i file del progetto nella directory di lavoro
COPY app/ .

# Compiliamo l'applicazione Go per l'architettura di AWS Lambda
RUN GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o main main.go

# Creiamo una nuova immagine per il deployment
FROM amazonlinux:2

# Installiamo le dipendenze richieste da AWS Lambda (libc, etc.)
RUN yum install -y \
    ca-certificates \
    && yum clean all

# Impostiamo la directory di lavoro per Lambda
WORKDIR /app

# Copiamo il binario compilato dalla fase di build
COPY --from=builder /app/main .

# Impostiamo i permessi di esecuzione per il binario
RUN chmod +x main

# Definiamo l'handler per la Lambda
CMD ["main"]
