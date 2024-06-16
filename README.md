# Notetify - Notes and Reminders Application

This project is a simple Notes and Reminders application built with Node.js, Express, and MySQL. It allows users to register, login, create notes, set reminders, and manage their data securely using JWT authentication.

## Features
- User registration and login with password hashing (bcrypt)
- JWT-based authentication for secure API access
- CRUD operations for notes
- CRUD operations for reminders
- Password reset functionality via email (nodemailer)
- Token-based authentication and authorization

## Prerequisites
- Node.js (v14 or higher)
- MySQL database
- A Gmail account for sending password reset emails (or another SMTP service)

## Installation

1. **Clone the repository:**
    ```sh
    git clone https://github.com/fach3f/Notetify-Backend.git
    cd Notetify-Backend
    ```

2. **Install dependencies:**
    ```sh
    npm install
    ```

3. **Create a `.env` file in the root directory and add the following environment variables:**
    ```
    JWT_SECRET=your_jwt_secret_key
    EMAIL_USER=your_email@gmail.com
    EMAIL_PASS=your_email_password
    DB_HOST=your_database_host
    DB_USER=your_database_user
    DB_PASS=your_database_password
    DB_NAME=your_database_name
    ```

4. **Set up the MySQL database:**
    - Create a new MySQL database.
    - Import the provided `schema.sql` file to create the required tables:
        ```sh
        mysql -u your_database_user -p your_database_name < schema.sql
        ```

## Running the Application

1. **Start the server:**
    ```sh
    npm start
    ```

2. **The application will be running on `http://localhost:3000`.**

## API Endpoints

### Authentication

- **Register a new user:**
    ```
    POST /register
    {
        "username": "exampleuser",
        "email": "user@example.com",
        "password": "password123"
    }
    ```

- **Login:**
    ```
    POST /login
    {
        "email": "user@example.com",
        "password": "password123"
    }
    ```

### Notes

- **Create a note:**
    ```
    POST /notes
    Headers: { "Authorization": "Bearer <token>" }
    {
        "title": "Note Title",
        "content": "Note content"
    }
    ```

- **Get all notes:**
    ```
    GET /notes
    Headers: { "Authorization": "Bearer <token>" }
    ```

- **Get a note by ID:**
    ```
    GET /notes/{noteId}
    Headers: { "Authorization": "Bearer <token>" }
    ```

- **Update a note:**
    ```
    PUT /notes/{noteId}
    Headers: { "Authorization": "Bearer <token>" }
    {
        "title": "Updated Title",
        "content": "Updated content"
    }
    ```

- **Delete a note:**
    ```
    DELETE /notes/{noteId}
    Headers: { "Authorization": "Bearer <token>" }
    ```

### Reminders

- **Create a reminder:**
    ```
    POST /reminders
    Headers: { "Authorization": "Bearer <token>" }
    {
        "noteId": 1,
        "title": "Reminder Title",
        "content": "Reminder content",
        "reminderDate": "2024-12-31T12:00:00Z"
    }
    ```

- **Get all reminders:**
    ```
    GET /reminders
    Headers: { "Authorization": "Bearer <token>" }
    ```

- **Get a reminder by ID:**
    ```
    GET /reminders/{reminderId}
    Headers: { "Authorization": "Bearer <token>" }
    ```

- **Update a reminder:**
    ```
    PUT /reminders/{reminderId}
    Headers: { "Authorization": "Bearer <token>" }
    {
        "title": "Updated Title",
        "reminderDate": "2024-12-31T12:00:00Z"
    }
    ```

- **Delete a reminder:**
    ```
    DELETE /reminders/{reminderId}
    Headers: { "Authorization": "Bearer <token>" }
    ```

### Password Reset

- **Request password reset:**
    ```
    POST /request-password-reset
    {
        "email": "user@example.com"
    }
    ```

- **Reset password:**
    ```
    POST /reset-password
    {
        "token": "reset_token_received_in_email",
        "newPassword": "newPassword123"
    }
    ```

## License
Muchammad Fahrizal
https://www.linkedin.com/in/muchammad-fahrizal/
