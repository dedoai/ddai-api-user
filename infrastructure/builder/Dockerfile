# Utilizziamo l'immagine ufficiale di Go per la fase di build
FROM public.ecr.aws/docker/library/golang:1.20 AS builder

# Impostiamo la directory di lavoro
WORKDIR /app

# Copiamo i file del progetto nella directory di lavoro
COPY app/ .

# Compiliamo l'applicazione Go per l'architettura di AWS Lambda
#RUN GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o main main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o main main.go

# Creiamo una nuova immagine per il deployment
FROM public.ecr.aws/docker/library/alpine:latest

# Usa apk invece di apt-get o yum per installare pacchetti su Alpine Linux
RUN apk update && apk add --no-cache \
    ca-certificates

# Impostiamo la directory di lavoro per Lambda
WORKDIR /app

# Copiamo il binario compilato dalla fase di build
COPY --from=builder /app/main .

# Impostiamo i permessi di esecuzione per il binario
RUN chmod +x main

# Definiamo l'handler per la Lambda
CMD ["./main"]
