# micro-doc-ingestion
Monorepo for microservices project of document ingestion

document-ingestion-service:
Complete working springboot service with 4 APIs.

user-serice:
Implementation in progress for user service with login, register and auth security features based on microservice architecture to work along with doc-ing service

Microservice Design Plan: 
1. document-ingestion-service: handling document related business logic
2. User-service: user related logic and security layer
3. api-gateway: to route all incoming api request to respective service
4. config-server: to handle project configuration
