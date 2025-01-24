# go-tasks-crud
crud api with golang gin framework for tasks with auth + rate limiting + pagination + test cases 

# Go Task Management API with Gin, GORM, JWT Authentication, Rate Limiting, and Pagination

This project implements a RESTful API for managing tasks using Go, the Gin web framework, GORM (Object-Relational Mapper), JWT (JSON Web Token) authentication, rate limiting, and pagination.

## Features

*   **CRUD Operations:** Create, Read, Update, and Delete tasks.
*   **JWT Authentication:** Secure API endpoints using JWT tokens.
*   **Rate Limiting:** Protect the API from abuse with rate limiting.
*   **Pagination:** Handle large datasets efficiently with pagination.
*   **Database Migrations:** Uses GORM AutoMigrate for easy database schema management.

## Technologies Used

*   Go
*   Gin Web Framework
*   GORM (Go Object Relational Mapping)
*   PostgreSQL
*   JWT (JSON Web Tokens)
*   `juju/ratelimit` (Rate limiting)
*   `testify/assert` (Testing)

## Prerequisites

*   Go (version 1.21 or later)
*   PostgreSQL database
*   Docker (Optional, for containerized deployment)

## Setup

1.  **Clone the repository:**

```bash
git clone [https://github.com/yourusername/your-repo-name.git](https://github.com/yourusername/your-repo-name.git)
cd your-repo-name/app