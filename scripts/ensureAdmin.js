import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';

dotenv.config();

const AdminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true },
  email: { type: String, required: true, trim: true, lowercase: true }
}, { timestamps: true });

const Admin = mongoose.model('Admin', AdminSchema);

async function ensureAdmin() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ Connected to MongoDB');

    const existingAdmin = await Admin.findOne({ username: 'admin@rightyway' });
    
    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash('rightyway@2025', 12);
      const admin = new Admin({
        username: 'admin@rightyway',
        password: hashedPassword,
        email: 'admin@rightyway.com'
      });
      
      await admin.save();
      console.log('✅ Admin user created successfully');
      console.log('Username: admin@rightyway');
      console.log('Password: rightyway@2025');
    } else {
      console.log('✅ Admin user already exists');
    }
    
    await mongoose.connection.close();
    process.exit(0);
  } catch (error) {
    console.error('❌ Error ensuring admin user:', error);
    process.exit(1);
  }
}

ensureAdmin();