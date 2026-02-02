# API Gateway

## Description
API Gateway acts as a single entry point for all client requests.
It routes requests to backend microservices using Eureka and
handles cross-cutting concerns like security and logging.

## Tech Stack
- Spring Boot
- Spring Cloud Gateway
- Eureka Client

## Port
8080

## How to Run
mvn spring-boot:run

## application.properties
server.port=8080
spring.application.name=api-gateway

spring.cloud.gateway.discovery.locator.enabled=true

eureka.client.service-url.defaultZone=http://localhost:8761/eureka
