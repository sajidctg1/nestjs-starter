# NestJS Project Structure - Feature-Based Architecture

```
src/
├── main.ts
├── app.module.ts
├── app.controller.ts
├── app.service.ts
├── common/
│   ├── constants/
│   │   ├── index.ts
│   │   ├── app.constants.ts
│   │   ├── auth.constants.ts
│   │   └── validation.constants.ts
│   ├── decorators/
│   │   ├── index.ts
│   │   ├── auth.decorator.ts
│   │   ├── roles.decorator.ts
│   │   └── user.decorator.ts
│   ├── dto/
│   │   ├── index.ts
│   │   ├── pagination.dto.ts
│   │   └── response.dto.ts
│   ├── enums/
│   │   ├── index.ts
│   │   ├── user-role.enum.ts
│   │   ├── user-status.enum.ts
│   │   └── product-status.enum.ts
│   ├── exceptions/
│   │   ├── index.ts
│   │   ├── business.exception.ts
│   │   └── validation.exception.ts
│   ├── filters/
│   │   ├── index.ts
│   │   ├── http-exception.filter.ts
│   │   └── validation-exception.filter.ts
│   ├── guards/
│   │   ├── index.ts
│   │   ├── jwt-auth.guard.ts
│   │   ├── roles.guard.ts
│   │   └── throttle.guard.ts
│   ├── interceptors/
│   │   ├── index.ts
│   │   ├── response.interceptor.ts
│   │   ├── logging.interceptor.ts
│   │   └── timeout.interceptor.ts
│   ├── interfaces/
│   │   ├── index.ts
│   │   ├── jwt-payload.interface.ts
│   │   ├── response.interface.ts
│   │   └── pagination.interface.ts
│   ├── middleware/
│   │   ├── index.ts
│   │   ├── logger.middleware.ts
│   │   └── cors.middleware.ts
│   ├── pipes/
│   │   ├── index.ts
│   │   ├── validation.pipe.ts
│   │   └── transform.pipe.ts
│   ├── utils/
│   │   ├── index.ts
│   │   ├── bcrypt.util.ts
│   │   ├── jwt.util.ts
│   │   ├── validation.util.ts
│   │   └── date.util.ts
│   └── index.ts
├── core/
│   ├── config/
│   │   ├── index.ts
│   │   ├── app.config.ts
│   │   ├── database.config.ts
│   │   ├── jwt.config.ts
│   │   ├── mail.config.ts
│   │   └── validation.schema.ts
│   ├── database/
│   │   ├── index.ts
│   │   ├── database.module.ts
│   │   ├── database.providers.ts
│   │   ├── migrations/
│   │   │   ├── 001_create_users_table.ts
│   │   │   ├── 002_create_products_table.ts
│   │   │   └── 003_create_password_resets_table.ts
│   │   └── seeds/
│   │       ├── user.seed.ts
│   │       └── product.seed.ts
│   ├── entities/
│   │   ├── index.ts
│   │   ├── base.entity.ts
│   │   ├── user.entity.ts
│   │   ├── product.entity.ts
│   │   └── password-reset.entity.ts
│   ├── security/
│   │   ├── index.ts
│   │   ├── security.module.ts
│   │   ├── hash.service.ts
│   │   ├── jwt.service.ts
│   │   └── encryption.service.ts
│   ├── mail/
│   │   ├── index.ts
│   │   ├── mail.module.ts
│   │   ├── mail.service.ts
│   │   └── templates/
│   │       ├── welcome.template.ts
│   │       ├── reset-password.template.ts
│   │       └── account-verification.template.ts
│   ├── logging/
│   │   ├── index.ts
│   │   ├── logging.module.ts
│   │   ├── logging.service.ts
│   │   └── winston.config.ts
│   └── index.ts
├── features/
│   ├── auth/
│   │   ├── auth.module.ts
│   │   ├── auth.controller.ts
│   │   ├── auth.service.ts
│   │   ├── strategies/
│   │   │   ├── index.ts
│   │   │   ├── jwt.strategy.ts
│   │   │   └── local.strategy.ts
│   │   ├── dto/
│   │   │   ├── index.ts
│   │   │   ├── signin.dto.ts
│   │   │   ├── signup.dto.ts
│   │   │   ├── reset-password.dto.ts
│   │   │   ├── forgot-password.dto.ts
│   │   │   └── change-password.dto.ts
│   │   ├── interfaces/
│   │   │   ├── index.ts
│   │   │   ├── auth-response.interface.ts
│   │   │   └── jwt-payload.interface.ts
│   │   └── tests/
│   │       ├── auth.controller.spec.ts
│   │       └── auth.service.spec.ts
│   ├── user-management/
│   │   ├── user-management.module.ts
│   │   ├── controllers/
│   │   │   ├── index.ts
│   │   │   ├── users.controller.ts
│   │   │   └── profile.controller.ts
│   │   ├── services/
│   │   │   ├── index.ts
│   │   │   ├── users.service.ts
│   │   │   └── profile.service.ts
│   │   ├── repositories/
│   │   │   ├── index.ts
│   │   │   └── user.repository.ts
│   │   ├── dto/
│   │   │   ├── index.ts
│   │   │   ├── create-user.dto.ts
│   │   │   ├── update-user.dto.ts
│   │   │   ├── update-profile.dto.ts
│   │   │   ├── user-query.dto.ts
│   │   │   └── user-response.dto.ts
│   │   ├── interfaces/
│   │   │   ├── index.ts
│   │   │   └── user-filter.interface.ts
│   │   └── tests/
│   │       ├── users.controller.spec.ts
│   │       ├── users.service.spec.ts
│   │       └── profile.service.spec.ts
│   ├── product-management/
│   │   ├── product-management.module.ts
│   │   ├── controllers/
│   │   │   ├── index.ts
│   │   │   ├── products.controller.ts
│   │   │   └── categories.controller.ts
│   │   ├── services/
│   │   │   ├── index.ts
│   │   │   ├── products.service.ts
│   │   │   └── categories.service.ts
│   │   ├── repositories/
│   │   │   ├── index.ts
│   │   │   ├── product.repository.ts
│   │   │   └── category.repository.ts
│   │   ├── dto/
│   │   │   ├── index.ts
│   │   │   ├── create-product.dto.ts
│   │   │   ├── update-product.dto.ts
│   │   │   ├── product-query.dto.ts
│   │   │   ├── product-response.dto.ts
│   │   │   ├── create-category.dto.ts
│   │   │   └── update-category.dto.ts
│   │   ├── interfaces/
│   │   │   ├── index.ts
│   │   │   └── product-filter.interface.ts
│   │   └── tests/
│   │       ├── products.controller.spec.ts
│   │       ├── products.service.spec.ts
│   │       └── categories.service.spec.ts
│   └── index.ts
├── config/
│   ├── development.env
│   ├── production.env
│   ├── test.env
│   └── .env.example
└── test/
    ├── app.e2e-spec.ts
    ├── auth.e2e-spec.ts
    ├── users.e2e-spec.ts
    ├── products.e2e-spec.ts
    └── jest-e2e.json
```

## Key Structure Explanations

### 📁 **Common Folder**
Contains shared utilities, decorators, guards, filters, and other reusable components that can be used across all features.

- **decorators/**: Custom decorators for authentication, roles, etc.
- **dto/**: Base DTOs for pagination, responses
- **enums/**: Application-wide enumerations
- **guards/**: JWT auth guard, roles guard, throttling
- **interceptors/**: Response transformation, logging
- **pipes/**: Validation and transformation pipes
- **utils/**: Helper functions for bcrypt, JWT, validation

### 📁 **Core Folder**
Contains core application infrastructure and foundational services.

- **config/**: Configuration management for database, JWT, mail
- **database/**: Database setup, migrations, seeds
- **entities/**: TypeORM entities for database models
- **security/**: Core security services (hashing, encryption, JWT)
- **mail/**: Email service with templates
- **logging/**: Centralized logging configuration

### 📁 **Features Folder**
Contains business logic organized by feature domains.

#### 🔐 **Auth Feature**
- Sign in/Sign up functionality
- Password reset flow
- JWT token management
- Authentication strategies

#### 👥 **User Management Feature**
- User CRUD operations
- Profile management
- User search and filtering
- Role-based access control

#### 📦 **Product Management Feature**
- Product CRUD operations
- Category management
- Product search and filtering
- Inventory management

## Key Files Overview

### Main Application Files
- `main.ts` - Application bootstrap
- `app.module.ts` - Root module with feature imports
- `app.controller.ts` - Health check and basic routes

### Configuration
- Environment-specific configuration files
- Validation schemas for configuration
- Database connection setup

### Security Implementation
- JWT-based authentication
- Password hashing with bcrypt
- Role-based authorization
- Request throttling and rate limiting

### Database Layer
- TypeORM entities with relationships
- Repository pattern implementation
- Database migrations and seeds
- Connection pooling configuration

## Benefits of This Structure

1. **Scalability**: Easy to add new features without affecting existing ones
2. **Maintainability**: Clear separation of concerns and responsibilities
3. **Testability**: Each feature can be tested independently
4. **Reusability**: Common utilities and services shared across features
5. **Team Development**: Multiple developers can work on different features simultaneously
6. **Domain-Driven**: Business logic organized by feature domains

This structure follows NestJS best practices and provides a solid foundation for enterprise-level applications with authentication, user management, and product management capabilities.
