# Spring Security JWT Template

This project is a template for implementing JWT-based authentication and authorization in a Spring Boot application. It provides a basic setup for user registration, login, and role-based access control, which can be easily extended and customized for your own projects.

## Features

-   **User Authentication:** Secure user login with email and password.
-   **JWT Generation:** Generates a JWT access token upon successful authentication.
-   **JWT Refresh Token:** Issues a secure, HTTP-only refresh token to generate new access tokens without requiring the user to log in again.
-   **Role-Based Access Control (RBAC):** Protects endpoints based on user roles (e.g., `USER`, `ADMIN`).
-   **Stateless API:** Designed as a stateless service, which is ideal for modern microservices architectures.
-   **Database Migrations:** Uses Flyway for managing database schema changes.

## Technologies Used

-   **Spring Boot:** For building the application.
-   **Spring Security:** For authentication and authorization.
-   **JJWT (Java JWT):** For creating and verifying JSON Web Tokens.
-   **Spring Data JPA:** For interacting with the database.
-   **MySQL:** As the relational database.
-   **Flyway:** For database migrations.
-   **Lombok:** To reduce boilerplate code.
-   **Maven:** For dependency management.

## Getting Started

### Prerequisites

-   Java 21 or later
-   Maven
-   MySQL

### Installation

1.  **Clone the repository:**

    ```sh
    git clone <your-repository-url>
    cd spring-api-starter
    ```

2.  **Configure the database:**

    Open `src/main/resources/application.yaml` and update the database connection details:

    ```yaml
    spring:
      datasource:
        url: jdbc:mysql://localhost:3306/your_database_name
        username: your_database_username
        password: your_database_password
    ```

3.  **Set up environment variables:**

    This project uses a `.env` file for managing sensitive information like the JWT secret. You will need to create a `.env` file in the root of the project and add the following:

    ```
    JWT_SECRET=your-super-secret-key
    ```

4.  **Run the application:**

    ```sh
    mvn spring-boot:run
    ```

    The application will start on `http://localhost:8080`.

## API Endpoints

### Authentication

-   `POST /auth/signup`: Register a new user.
-   `POST /auth/login`: Log in a user and receive a JWT access token and a refresh token (as an HTTP-only cookie).
-   `POST /auth/refresh`: Obtain a new access token using a valid refresh token.

### User

-   `GET /user`: A protected endpoint for authenticated users.
-   `GET /user/get-all`: A public endpoint to retrieve all users.

### Admin

-   `GET /admin/hello`: A protected endpoint accessible only by users with the `ADMIN` role.

## How It Works

1.  **User Registration (`/auth/signup`):** A new user is created with a hashed password and assigned a default role.
2.  **User Login (`/auth/login`):**
    -   The user provides their email and password.
    -   Spring Security's `AuthenticationManager` validates the credentials.
    -   If successful, `JwtService` generates two tokens:
        -   An **access token** with a short expiration time, returned in the response body.
        -   A **refresh token** with a longer expiration time, sent as a secure, HTTP-only cookie.
3.  **Accessing Protected Endpoints:**
    -   The client sends the access token in the `Authorization` header (`Bearer <token>`).
    -   The `JwtAuthenticationFilter` intercepts the request, validates the token, and sets the user's authentication context.
4.  **Refreshing Tokens (`/auth/refresh`):**
    -   When the access token expires, the client sends a request to the `/auth/refresh` endpoint.
    -   The refresh token (from the cookie) is used to generate a new access token.

## Customization

-   **Roles:** Modify the `RoleName` enum in `src/main/java/com/codewithmosh/store/entities/RoleName.java` to add or remove roles.
-   **Security Configuration:** Adjust the security rules in `src/main/java/com/codewithmosh/store/config/SecurityConfig.java` to change endpoint permissions.
-   **JWT Expiration:** Change the token expiration times in `src/main/resources/application.yaml`.