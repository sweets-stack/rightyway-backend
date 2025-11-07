// server.js - Enhanced with Monthly Revenue, PDF Export, Stock Deduction, and Real-time Stats
import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import fs from 'fs';
import path from 'path';
import rateLimit from 'express-rate-limit';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config();

const app = express();

const PORT = process.env.PORT || 5000;

app.set('trust proxy', 1);

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}





// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(morgan('combined'));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use('/uploads', express.static(uploadsDir));

// Rate limiting - FIXED for Railway
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute window
  max: process.env.NODE_ENV === 'production' ? 500 : 100000,
  message: { error: 'Too many requests from this IP, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

if (process.env.NODE_ENV === 'production') {
  app.use('/api/', limiter);
  console.log('⚠️  Rate limiting enabled for production');
} else {
  console.log('✅ Rate limiting disabled for development');
}


// Cloudinary Configuration
if (process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
  });
  console.log('✅ Cloudinary configured');
} else {
  console.log('⚠️ Cloudinary not configured - using local storage');
}

// Multer configuration
const storage = multer.memoryStorage();
const upload = multer({ 
  storage,
  limits: { 
    fileSize: 10 * 1024 * 1024,
    files: 8
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/rightyway-aso-oke')
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// Mongoose Schemas
const productSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: [true, 'Product name is required'],
    trim: true,
    maxlength: [100, 'Product name cannot exceed 100 characters']
  },
  description: { 
    type: String, 
    required: [true, 'Product description is required'],
    trim: true,
    maxlength: [1000, 'Description cannot exceed 1000 characters']
  },
  price: { 
    type: Number, 
    required: [true, 'Product price is required'],
    min: [0, 'Price cannot be negative']
  },
  price_ngn: { 
    type: Number, 
    required: [true, 'Product price in NGN is required'],
    min: [0, 'Price cannot be negative']
  },
  category: { 
    type: String, 
    required: [true, 'Product category is required'],
    trim: true
  },
  images: [{ type: String }],
  colors: [{ type: String, trim: true }],
  inStock: { type: Boolean, default: true },
  featured: { type: Boolean, default: false },
  tags: [{ type: String, trim: true }],
  stock: { type: Number, default: 0, min: [0, 'Stock cannot be negative'] }
}, { 
  timestamps: true 
});

productSchema.index({ name: 'text', description: 'text', category: 'text' });
productSchema.index({ category: 1 });
productSchema.index({ featured: 1 });
productSchema.index({ inStock: 1 });

const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true },
  email: { type: String, required: true, trim: true, lowercase: true }
}, { timestamps: true });

const orderSchema = new mongoose.Schema({
  orderNumber: { type: String, required: true, unique: true },
  customer: {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, trim: true, lowercase: true },
    phone: { type: String, trim: true },
    address: {
      street: { type: String, required: true, trim: true },
      city: { type: String, required: true, trim: true },
      state: { type: String, required: true, trim: true },
      country: { type: String, required: true, trim: true },
      postalCode: { type: String, required: true, trim: true }
    }
  },
  items: [{
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    productName: { type: String, required: true, trim: true },
    price: { type: Number, required: true, min: 0 },
    quantity: { type: Number, required: true, min: 1 },
    color: { type: String, trim: true },
    images: [{ type: String }]
  }],
  subtotal: { type: Number, required: true, min: 0 },
  shippingFee: { type: Number, default: 0, min: 0 },
  total: { type: Number, required: true, min: 0 },
  status: { 
    type: String, 
    enum: ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'],
    default: 'pending'
  },
  paymentStatus: {
    type: String,
    enum: ['pending', 'paid', 'failed', 'refunded'],
    default: 'pending'
  },
  shippingMethod: { type: String, default: 'standard' },
  notes: { type: String, trim: true },
  trackingNumber: { type: String },
  isShippedToSales: { type: Boolean, default: false },
  statusHistory: [{
    status: { type: String },
    paymentStatus: { type: String },
    changedBy: { type: String },
    changedAt: { type: Date, default: Date.now },
    notes: { type: String }
  }]
}, { 
  timestamps: true 
});

orderSchema.index({ status: 1 });
orderSchema.index({ 'customer.email': 1 });
orderSchema.index({ createdAt: -1 });

const Product = mongoose.model('Product', productSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Order = mongoose.model('Order', orderSchema);

// ==================== ORDER STATUS AUTOMATION LOGIC ====================

const getAutoPaymentStatus = (orderStatus, currentPaymentStatus) => {
  const rules = {
    'pending': 'pending',
    'confirmed': 'paid',
    'processing': 'paid',
    'shipped': 'paid',
    'delivered': 'paid',
    'cancelled': currentPaymentStatus === 'paid' ? 'refunded' : 'failed'
  };
  
  return rules[orderStatus] || currentPaymentStatus;
};

const validStatusTransitions = {
  'pending': ['confirmed', 'cancelled'],
  'confirmed': ['processing', 'cancelled'],
  'processing': ['shipped', 'cancelled'],
  'shipped': ['delivered', 'cancelled'],
  'delivered': [],
  'cancelled': []
};

const canTransitionStatus = (currentStatus, newStatus) => {
  if (currentStatus === newStatus) return true;
  return validStatusTransitions[currentStatus]?.includes(newStatus) || false;
};

const getStatusMessage = (currentStatus, newStatus) => {
  const messages = {
    'pending_confirmed': 'Order confirmed and payment received',
    'confirmed_processing': 'Order is being prepared',
    'processing_shipped': 'Order has been shipped',
    'shipped_delivered': 'Order delivered successfully',
    'cancelled': 'Order has been cancelled'
  };
  
  return messages[`${currentStatus}_${newStatus}`] || `Status updated to ${newStatus}`;
};

// ==================== HELPER FUNCTIONS ====================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  console.log('🔐 Token verification attempt:', {
    path: req.path,
    hasAuthHeader: !!authHeader,
    hasToken: !!token,
    authHeader: authHeader ? 'Present' : 'Missing'
  });

  if (!token) {
    console.log('❌ No token provided for:', req.path);
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret', (err, user) => {
    if (err) {
      console.log('❌ Token verification failed:', err.message);
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    
    console.log('✅ Token verified for user:', user.username);
    req.user = user;
    next();
  });
};

const uploadImage = async (buffer, filename) => {
  if (process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY) {
    try {
      return new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          { 
            folder: 'rightyway-aso-oke/products',
            quality: 'auto',
            fetch_format: 'auto'
          },
          (error, result) => {
            if (error) {
              console.error('Cloudinary upload error:', error);
              reject(error);
            } else {
              resolve(result.secure_url);
            }
          }
        );
        uploadStream.end(buffer);
      });
    } catch (error) {
      console.error('Cloudinary upload failed:', error);
    }
  }

  try {
    const localFilename = `product-${Date.now()}-${Math.random().toString(36).substr(2, 9)}.jpg`;
    const filepath = path.join(uploadsDir, localFilename);
    await fs.promises.writeFile(filepath, buffer);
    return `/uploads/${localFilename}`;
  } catch (error) {
    console.error('Local storage upload failed:', error);
    return 'https://via.placeholder.com/600x400/000b4a/ffffff?text=Rightyway+Aso-Oke';
  }
};

const generateOrderNumber = async () => {
  const date = new Date();
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const prefix = `RW${year}${month}`;
  
  const lastOrder = await Order.findOne({ 
    orderNumber: new RegExp(`^${prefix}`) 
  }).sort({ orderNumber: -1 });
  
  if (!lastOrder) {
    return `${prefix}0001`;
  }
  
  const lastNumber = parseInt(lastOrder.orderNumber.slice(-4));
  return `${prefix}${String(lastNumber + 1).padStart(4, '0')}`;
};

const generateTrackingNumber = () => {
  return 'RW' + Date.now().toString(36) + Math.random().toString(36).substr(2, 5).toUpperCase();
};

const caseInsensitiveSearch = (query) => {
  if (!query) return {};
  
  return {
    $or: [
      { name: { $regex: query, $options: 'i' } },
      { description: { $regex: query, $options: 'i' } },
      { category: { $regex: query, $options: 'i' } },
      { tags: { $in: [new RegExp(query, 'i')] } }
    ]
  };
};

// ==================== DEBUG MIDDLEWARE ====================
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('Body:', JSON.stringify(req.body));
  }
  next();
});


// ==================== IMPROVED AUTHENTICATION ROUTES ====================

app.post('/api/auth/login', async (req, res) => {
  try {
    console.log('Login attempt:', req.body);
    
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Username and password required' 
      });
    }

    const admin = await Admin.findOne({ username });
    if (!admin) {
      console.log('Admin not found:', username);
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials' 
      });
    }

    const isValidPassword = await bcrypt.compare(password, admin.password);
    if (!isValidPassword) {
      console.log('Invalid password for:', username);
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials' 
      });
    }

    const token = jwt.sign(
      { id: admin._id, username: admin.username },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '24h' }
    );

    console.log('Login successful for:', username);
    
    res.json({ 
      success: true,
      token, 
      admin: { 
        id: admin._id, 
        username: admin.username, 
        email: admin.email 
      } 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Server error during login' 
    });
  }
});

app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({ 
    success: true,
    valid: true, 
    user: req.user 
  });
});

// Add a test endpoint to check if auth routes are working
app.get('/api/auth/test', (req, res) => {
  res.json({ 
    success: true,
    message: 'Auth routes are working!',
    timestamp: new Date().toISOString()
  });
});

// ==================== PRODUCT ROUTES ====================

app.get('/api/products', async (req, res) => {
  try {
    const { category, featured, inStock, search, page = 1, limit = 50 } = req.query;
    const filter = {};

    if (category) filter.category = new RegExp(category, 'i');
    if (featured !== undefined) filter.featured = featured === 'true';
    if (inStock !== undefined) filter.inStock = inStock === 'true';
    if (search) {
      Object.assign(filter, caseInsensitiveSearch(search));
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const [products, total] = await Promise.all([
      Product.find(filter)
        .sort({ createdAt: -1 })
        .limit(parseInt(limit))
        .skip(skip)
        .lean(),
      Product.countDocuments(filter)
    ]);

    res.set('Cache-Control', 'public, max-age=300');
    
    res.json({
      products,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id).lean();
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    res.set('Cache-Control', 'public, max-age=300');
    res.json(product);
  } catch (error) {
    console.error('Error fetching product:', error);
    res.status(500).json({ error: 'Failed to fetch product' });
  }
});

app.post('/api/products', authenticateToken, upload.array('images', 8), async (req, res) => {
  try {
    const { name, description, price, category, colors, inStock, featured, tags, stock } = req.body;

    if (!name || !description || !price || !category || stock === undefined) {
      return res.status(400).json({ error: 'Missing required fields: name, description, price, category, stock' });
    }

    let imageUrls = [];
    if (req.files && req.files.length > 0) {
      const uploadPromises = req.files.map(file => uploadImage(file.buffer, file.originalname));
      imageUrls = await Promise.all(uploadPromises);
    }

    const colorsArray = colors ? colors.split(',').map(c => c.trim()).filter(c => c) : [];
    const tagsArray = tags ? tags.split(',').map(t => t.trim()).filter(t => t) : [];
    const stockNumber = parseInt(stock);
    const priceNumber = parseFloat(price);

    const product = new Product({
      name: name.trim(),
      description: description.trim(),
      price: priceNumber,
      price_ngn: priceNumber,
      category: category.trim(),
      images: imageUrls,
      colors: colorsArray,
      stock: stockNumber,
      inStock: inStock === 'true' || inStock === true || stockNumber > 0,
      featured: featured === 'true' || featured === true,
      tags: tagsArray
    });

    await product.save();
    res.status(201).json(product);
  } catch (error) {
    console.error('Error creating product:', error);
    res.status(500).json({ error: 'Failed to create product: ' + error.message });
  }
});

app.put('/api/products/:id', authenticateToken, upload.array('images', 8), async (req, res) => {
  try {
    const { name, description, price, category, colors, inStock, featured, tags, stock, existingImages } = req.body;

    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    let newImageUrls = [];
    if (req.files && req.files.length > 0) {
      const uploadPromises = req.files.map(file => uploadImage(file.buffer, file.originalname));
      newImageUrls = await Promise.all(uploadPromises);
    }

    let existingImagesArray = [];
    try {
      if (existingImages) {
        existingImagesArray = typeof existingImages === 'string' 
          ? JSON.parse(existingImages) 
          : existingImages;
      } else {
        existingImagesArray = product.images || [];
      }
    } catch (parseError) {
      console.error('Error parsing existingImages:', parseError);
      existingImagesArray = product.images || [];
    }

    if (!Array.isArray(existingImagesArray)) {
      existingImagesArray = [];
    }

    const finalImages = [...existingImagesArray, ...newImageUrls];

    product.name = name ? name.trim() : product.name;
    product.description = description ? description.trim() : product.description;
    product.price = price ? parseFloat(price) : product.price;
    product.price_ngn = price ? parseFloat(price) : product.price_ngn;
    product.category = category ? category.trim() : product.category;
    product.images = finalImages;
    
    if (colors !== undefined) {
      product.colors = colors ? colors.split(',').map(c => c.trim()).filter(c => c) : [];
    }
    
    if (tags !== undefined) {
      product.tags = tags ? tags.split(',').map(t => t.trim()).filter(t => t) : [];
    }
    
    if (stock !== undefined) {
      product.stock = parseInt(stock);
      product.inStock = inStock !== undefined ? (inStock === 'true' || inStock === true) : (product.stock > 0);
    }
    
    if (featured !== undefined) {
      product.featured = featured === 'true' || featured === true;
    }

    await product.save();
    res.json(product);
  } catch (error) {
    console.error('Error updating product:', error);
    res.status(500).json({ error: 'Failed to update product: ' + error.message });
  }
});

app.delete('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json({ message: 'Product deleted successfully', product });
  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(500).json({ error: 'Failed to delete product' });
  }
});

app.put('/api/products/:id/stock', authenticateToken, async (req, res) => {
  try {
    const { stock } = req.body;
    
    if (stock === undefined || stock === null) {
      return res.status(400).json({ error: 'Stock quantity is required' });
    }

    const stockNumber = parseInt(stock);
    if (isNaN(stockNumber) || stockNumber < 0) {
      return res.status(400).json({ error: 'Invalid stock quantity' });
    }

    const product = await Product.findByIdAndUpdate(
      req.params.id,
      { 
        stock: stockNumber,
        inStock: stockNumber > 0
      },
      { new: true }
    );

    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    res.json(product);
  } catch (error) {
    console.error('Error updating stock:', error);
    res.status(500).json({ error: 'Failed to update stock' });
  }
});

// ==================== ORDER ROUTES WITH AUTOMATION ====================

app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const { status, page = 1, limit = 20, search } = req.query;
    const filter = {};
    
    if (status && status !== 'all') {
      filter.status = status;
    }

    if (search) {
      filter.$or = [
        { orderNumber: { $regex: search, $options: 'i' } },
        { 'customer.name': { $regex: search, $options: 'i' } },
        { 'customer.email': { $regex: search, $options: 'i' } }
      ];
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const [orders, total] = await Promise.all([
      Order.find(filter)
        .populate('items.product', 'name images')
        .sort({ createdAt: -1 })
        .limit(parseInt(limit))
        .skip(skip)
        .lean(),
      Order.countDocuments(filter)
    ]);

    res.json({
      orders,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Monthly Revenue Endpoint
app.get('/api/orders/monthly-revenue', authenticateToken, async (req, res) => {
  try {
    const monthlyRevenue = await Order.aggregate([
      {
        $match: {
          status: { $in: ['delivered', 'shipped', 'processing', 'confirmed'] }
        }
      },
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' }
          },
          totalRevenue: { $sum: '$total' },
          orderCount: { $sum: 1 }
        }
      },
      {
        $sort: { '_id.year': -1, '_id.month': -1 }
      },
      {
        $limit: 12 // Last 12 months
      }
    ]);

    res.json(monthlyRevenue);
  } catch (error) {
    console.error('Error fetching monthly revenue:', error);
    res.status(500).json({ error: 'Failed to fetch monthly revenue' });
  }
});

// Revenue Export Endpoint
app.get('/api/orders/revenue-export', authenticateToken, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;

    if (!startDate || !endDate) {
      return res.status(400).json({ error: 'Start date and end date are required' });
    }

    const start = new Date(startDate);
    start.setHours(0, 0, 0, 0);
    
    const end = new Date(endDate);
    end.setHours(23, 59, 59, 999);

    const orders = await Order.find({
      createdAt: {
        $gte: start,
        $lte: end
      },
      status: { $in: ['delivered', 'shipped', 'processing', 'confirmed'] }
    })
    .select('orderNumber customer createdAt status total items')
    .sort({ createdAt: -1 })
    .lean();

    const totalRevenue = orders.reduce((sum, order) => sum + order.total, 0);
    const totalOrders = orders.length;
    const averageOrderValue = totalOrders > 0 ? totalRevenue / totalOrders : 0;

    res.json({
      orders,
      summary: {
        totalOrders,
        totalRevenue,
        averageOrderValue: Math.round(averageOrderValue * 100) / 100,
        dateRange: {
          start: start.toISOString(),
          end: end.toISOString()
        }
      }
    });
  } catch (error) {
    console.error('Error fetching revenue export:', error);
    res.status(500).json({ error: 'Failed to fetch revenue export data' });
  }
});

app.get('/api/orders/:id', authenticateToken, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id)
      .populate('items.product', 'name images colors');
    
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    res.json(order);
  } catch (error) {
    console.error('Error fetching order:', error);
    res.status(500).json({ error: 'Failed to fetch order' });
  }
});

app.post('/api/orders', async (req, res) => {
  try {
    const { customer, items, shippingFee, shippingMethod, notes } = req.body;

    if (!customer || !items || items.length === 0) {
      return res.status(400).json({ error: 'Customer info and items are required' });
    }

    if (!customer.name || !customer.email || !customer.address?.street || !customer.address?.city || !customer.address?.state) {
      return res.status(400).json({ error: 'Complete customer information is required' });
    }

    const subtotal = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    const total = subtotal + (parseFloat(shippingFee) || 0);

    const order = new Order({
      orderNumber: await generateOrderNumber(),
      customer,
      items,
      subtotal,
      shippingFee: parseFloat(shippingFee) || 0,
      total,
      shippingMethod: shippingMethod || 'standard',
      notes,
      trackingNumber: generateTrackingNumber(),
      statusHistory: [{
        status: 'pending',
        paymentStatus: 'pending',
        changedBy: 'system',
        notes: 'Order created'
      }]
    });

    await order.save();
    
    res.status(201).json(order);
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// ENHANCED: Manual order with stock deduction
app.post('/api/orders/manual', authenticateToken, async (req, res) => {
  try {
    const { customer, items, shippingFee, shippingMethod, notes } = req.body;

    if (!customer || !items || items.length === 0) {
      return res.status(400).json({ error: 'Customer info and items are required' });
    }

    const missingFields = [];
    if (!customer.name) missingFields.push('customer name');
    if (!customer.email) missingFields.push('customer email');
    if (!customer.address?.street) missingFields.push('street address');
    if (!customer.address?.city) missingFields.push('city');
    if (!customer.address?.state) missingFields.push('state');
    if (!customer.address?.country) missingFields.push('country');
    if (!customer.address?.postalCode) missingFields.push('postal code');

    if (missingFields.length > 0) {
      return res.status(400).json({ 
        error: `Missing required fields: ${missingFields.join(', ')}` 
      });
    }

    // Validate and deduct stock for products
    const stockUpdates = [];
    for (const item of items) {
      if (item.product) {
        const product = await Product.findById(item.product);
        if (!product) {
          return res.status(404).json({ error: `Product not found: ${item.productName}` });
        }
        
        if (product.stock < item.quantity) {
          return res.status(400).json({ 
            error: `Insufficient stock for ${product.name}. Available: ${product.stock}, Requested: ${item.quantity}` 
          });
        }
        
        stockUpdates.push({
          productId: product._id,
          newStock: product.stock - item.quantity
        });
      }
    }

    const subtotal = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    const total = subtotal + (parseFloat(shippingFee) || 0);

    const order = new Order({
      orderNumber: await generateOrderNumber(),
      customer,
      items,
      subtotal,
      shippingFee: parseFloat(shippingFee) || 0,
      total,
      shippingMethod: shippingMethod || 'standard',
      notes,
      trackingNumber: generateTrackingNumber(),
      status: 'confirmed',
      paymentStatus: 'paid',
      statusHistory: [{
        status: 'confirmed',
        paymentStatus: 'paid',
        changedBy: req.user.username,
        notes: 'Manual order created - payment confirmed'
      }]
    });

    // Update stock for all products
    for (const update of stockUpdates) {
      await Product.findByIdAndUpdate(
        update.productId,
        { 
          stock: update.newStock,
          inStock: update.newStock > 0
        }
      );
    }

    await order.save();
    
    res.status(201).json({
      order,
      stockUpdates: stockUpdates.map(u => ({
        productId: u.productId,
        newStock: u.newStock
      }))
    });
  } catch (error) {
    console.error('Error creating manual order:', error);
    res.status(500).json({ error: 'Failed to create manual order: ' + error.message });
  }
});

app.put('/api/orders/:id/status', authenticateToken, async (req, res) => {
  try {
    const { status, trackingNumber, notes } = req.body;
    
    if (!status) {
      return res.status(400).json({ error: 'Status is required' });
    }

    const order = await Order.findById(req.params.id);
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    if (!canTransitionStatus(order.status, status)) {
      const allowedStatuses = validStatusTransitions[order.status];
      return res.status(400).json({ 
        error: `Invalid status transition from "${order.status}" to "${status}". Allowed transitions: ${allowedStatuses.join(', ') || 'none (final state)'}`
      });
    }

    let finalTrackingNumber = trackingNumber;
    if (status === 'shipped' && !trackingNumber && !order.trackingNumber) {
      finalTrackingNumber = generateTrackingNumber();
    }

    const newPaymentStatus = getAutoPaymentStatus(status, order.paymentStatus);
    const statusMessage = getStatusMessage(order.status, status);

    order.status = status;
    order.paymentStatus = newPaymentStatus;
    
    if (finalTrackingNumber) {
      order.trackingNumber = finalTrackingNumber;
    }

    if (status === 'shipped' && !order.isShippedToSales) {
      order.isShippedToSales = true;
    }

    order.statusHistory.push({
      status: status,
      paymentStatus: newPaymentStatus,
      changedBy: req.user.username,
      changedAt: new Date(),
      notes: notes || statusMessage
    });

    await order.save();
    
    res.json({
      order,
      message: statusMessage,
      automaticUpdates: {
        paymentStatus: newPaymentStatus !== order.paymentStatus ? 'updated automatically' : 'no change',
        trackingNumber: finalTrackingNumber && !trackingNumber ? 'generated automatically' : 'no change'
      }
    });
  } catch (error) {
    console.error('Error updating order status:', error);
    res.status(500).json({ error: 'Failed to update order status' });
  }
});

app.put('/api/orders/:id/payment', authenticateToken, async (req, res) => {
  try {
    const { paymentStatus } = req.body;
    
    if (!paymentStatus) {
      return res.status(400).json({ error: 'Payment status is required' });
    }

    const order = await Order.findById(req.params.id);
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    order.paymentStatus = paymentStatus;
    
    order.statusHistory.push({
      status: order.status,
      paymentStatus: paymentStatus,
      changedBy: req.user.username,
      notes: 'Payment status updated manually'
    });

    await order.save();
    
    res.json(order);
  } catch (error) {
    console.error('Error updating payment status:', error);
    res.status(500).json({ error: 'Failed to update payment status' });
  }
});

// ==================== IMPROVED ORDER STATS ENDPOINT ====================
// FIXED: Sales history now counts both shipped AND delivered orders
app.get('/api/orders-stats', authenticateToken, async (req, res) => {
  try {
    const [
      totalOrders, 
      pendingOrders, 
      completedOrders, 
      revenueResult, 
      salesHistory,
      processingOrders,
      shippedOrders
    ] = await Promise.all([
      // Total orders count
      Order.countDocuments(),
      
      // Pending orders (pending + confirmed)
      Order.countDocuments({ status: { $in: ['pending', 'confirmed'] } }),
      
      // Completed/Delivered orders
      Order.countDocuments({ status: 'delivered' }),
      
      // Total revenue from delivered orders
      Order.aggregate([
        { 
          $match: { 
            status: 'delivered',
            paymentStatus: 'paid'
          } 
        },
        { 
          $group: { 
            _id: null, 
            total: { $sum: '$total' } 
          } 
        }
      ]),
      
      // FIXED: Sales history - all orders that have been shipped OR delivered
      Order.countDocuments({ 
        status: { $in: ['shipped', 'delivered'] }
      }),
      
      // Processing orders
      Order.countDocuments({ status: 'processing' }),
      
      // Shipped orders
      Order.countDocuments({ status: 'shipped' })
    ]);
    
    const totalRevenue = revenueResult.length > 0 ? revenueResult[0].total : 0;

    // Calculate additional metrics
    const conversionRate = totalOrders > 0 
      ? Math.round((completedOrders / totalOrders) * 100) 
      : 0;

    const averageOrderValue = completedOrders > 0 
      ? Math.round(totalRevenue / completedOrders) 
      : 0;

    res.json({
      totalOrders,
      pendingOrders,
      completedOrders,
      processingOrders,
      shippedOrders,
      totalRevenue,
      salesHistory, // This now includes both shipped AND delivered orders
      conversionRate,
      averageOrderValue,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error fetching order stats:', error);
    res.status(500).json({ error: 'Failed to fetch order statistics: ' + error.message });
  }
});

app.get('/api/orders-sales', authenticateToken, async (req, res) => {
  try {
    const sales = await Order.find({ 
      status: { $in: ['shipped', 'delivered'] }
    })
    .populate('items.product', 'name images')
    .sort({ updatedAt: -1 })
    .limit(100);

    res.json(sales);
  } catch (error) {
    console.error('Error fetching sales history:', error);
    res.status(500).json({ error: 'Failed to fetch sales history' });
  }
});

app.get('/api/track/:trackingNumber', async (req, res) => {
  try {
    const { trackingNumber } = req.params;
    
    const order = await Order.findOne({ trackingNumber })
      .populate('items.product', 'name images');
    
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    res.json({
      orderNumber: order.orderNumber,
      status: order.status,
      trackingNumber: order.trackingNumber,
      customer: {
        name: order.customer.name
      },
      estimatedDelivery: order.status === 'shipped' ? '3-5 business days' : 'Processing',
      lastUpdated: order.updatedAt
    });
  } catch (error) {
    console.error('Error tracking order:', error);
    res.status(500).json({ error: 'Failed to track order' });
  }
});

// ==================== CONTACT FORM ROUTE ====================

app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, phone, message, type } = req.body;

    if (!name || !email || !message) {
      return res.status(400).json({ error: 'Name, email, and message are required' });
    }

    console.log('Contact form submission:', { name, email, phone, message, type });

    res.json({ message: 'Message received successfully. We will get back to you soon!' });
  } catch (error) {
    console.error('Error processing contact form:', error);
    res.status(500).json({ error: 'Failed to process contact form' });
  }
});

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    environment: process.env.NODE_ENV || 'development'
  });
});

app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

app.use((err, req, res, next) => {
  console.error('Error stack:', err.stack);
  
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 10MB.' });
    }
    if (err.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({ error: 'Too many files. Maximum is 8 files.' });
    }
  }
  
  res.status(500).json({ 
    error: process.env.NODE_ENV === 'production' 
      ? 'Something went wrong!' 
      : err.message 
  });
});

process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  await mongoose.connection.close();
  process.exit(0);
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 API available at http://localhost:${PORT}/api`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log('✅ Automatic payment status updates enabled');
  console.log('✅ Order status flow validation enabled');
  console.log('✅ Monthly revenue tracking enabled');
  console.log('✅ Revenue PDF export enabled');
  console.log('✅ Automatic stock deduction enabled');
  console.log('✅ Real-time sales history tracking enabled');
});