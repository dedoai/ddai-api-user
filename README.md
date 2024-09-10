
# ddai-api-user

![Go](https://img.shields.io/badge/Go-1.XX-blue)
![AWS Lambda](https://img.shields.io/badge/AWS-Lambda-yellow)
![License](https://img.shields.io/badge/License-MIT-green)

**dedoAI** - API User Management Service

---

## Overview

This repository contains the `ddai-api-user` service, an AWS Lambda function developed in **Go** that exposes a set of CRUD APIs for user management and profile handling. This microservice is designed to efficiently manage user data, enabling seamless integration into various applications requiring user profile functionalities.

---

## Features

- **User CRUD Operations**: Create, Read, Update, and Delete users.
- **Profile Management**: Handles detailed profile management for users.
- **Scalable Architecture**: Built on AWS Lambda to ensure scalability and cost-effectiveness.
- **Written in Go**: Efficient and performant backend logic.
- **Serverless Deployment**: Easily deployable as a serverless function using AWS services.

---

## Technologies

- **Go**: The service is implemented in Go for high performance and scalability.
- **AWS Lambda**: A serverless platform for running backend code without managing infrastructure.
- **API Gateway**: Exposes the Lambda functions as RESTful APIs.
- **DynamoDB (Optional)**: Can be integrated for storing user profiles.

---

## Getting Started

### Prerequisites

Before you start, ensure you have the following tools installed:

- **Go** (version 1.XX or higher)
- **AWS CLI**: To interact with AWS services.
- **SAM CLI**: AWS Serverless Application Model for local testing and deployment.
- **Docker** (optional): For local Lambda testing.

### Setup

1. Clone this repository:

    ```bash
    git clone https://github.com/dedoAI/ddai-api-user.git
    cd ddai-api-user
    ```

2. Install dependencies:

    ```bash
    go mod download
    ```

3. Set up your AWS environment (for local testing/deployment):

    ```bash
    aws configure
    ```

4. Use AWS SAM for local testing:

    ```bash
    sam local start-api
    ```

    You can now access the API locally at `http://localhost:3000`.

---

## API Endpoints

The following APIs are exposed for managing users:

| Method | Endpoint                | Description           |
|--------|-------------------------|-----------------------|
| GET    | `/users`                | Fetch all users       |
| GET    | `/users/{id}`           | Fetch a specific user |
| POST   | `/users`                | Create a new user     |
| PUT    | `/users/{id}`           | Update user details   |
| DELETE | `/users/{id}`           | Delete a user         |

---

## Deployment

To deploy the service to AWS, you can use the AWS SAM CLI:

1. Build the application:

    ```bash
    sam build
    ```

2. Deploy the application:

    ```bash
    sam deploy --guided
    ```

    Follow the prompts to specify your AWS region, stack name, and other settings.

---

## Configuration

The service can be configured through the `template.yaml` file, which defines the Lambda function, its API Gateway, and any other AWS resources required for the deployment.

### Example `template.yaml`

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  ApiUserFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: main
      Runtime: go1.x
      Environment:
        Variables:
          TABLE_NAME: UserTable
      Events:
        ApiGateway:
          Type: Api
          Properties:
            Path: /users
            Method: any
```

Modify this file as needed before deploying to your AWS environment.

---

## Testing

Unit tests can be run using the Go testing framework. Simply run:

```bash
go test ./...
```

You can also test the Lambda function locally using AWS SAM with:

```bash
sam local invoke ApiUserFunction
```

---

## Contributing

We welcome contributions! Please fork this repository, create a feature branch, and submit a pull request.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Contact

For further questions or support, please reach out to the **dedoAI** team:

- **Email**: support@dedoai.org
- **Website**: [dedoai.org](https://www.dedoai.org)
