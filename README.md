# spring-boot-examples-jwt-auth

## Examples on how to secure a REST API using a JWT token.

0. First, set up a minimalistic Spring Boot app (`pom.xml`,`ExampleApplication.java`, `ExampleController.java`).
1. Test the endpoint at [localhost:8080/example/hello](localhost:8080/example/hello)
2. Second, add the security dependency (`pom.xml`) and the security config (`application.yaml`, `JwtTokenFilter.java`).