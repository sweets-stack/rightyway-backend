# Rightyway Aso-Oke Backend API

## Quick Start

1. Install dependencies:
```bash
cd backend
npm install
```

2. Configure environment variables:
```bash
# Edit backend/.env with your credentials
```

3. Create admin user:
```bash
npm run seed
```

4. Start development server:
```bash
npm run dev
```

Server will run on http://localhost:5000

## Environment Variables

Copy `.env.example` to `.env` and configure:
- MongoDB connection string
- JWT secret
- Cloudinary credentials
- Email service credentials

## API Endpoints

### Authentication
- POST /api/auth/login - Admin login
- POST /api/auth/register - Register admin
- GET /api/auth/verify - Verify token

### Products
- GET /api/products - Get all products
- GET /api/products/:id - Get single product
- POST /api/products - Create product (auth required)
- PUT /api/products/:id - Update product (auth required)
- DELETE /api/products/:id - Delete product (auth required)

### Contact
- POST /api/contact - Submit contact/wholesale form

### Health
- GET /api/health - Server health check

## Deployment

See main project README for deployment instructions.
