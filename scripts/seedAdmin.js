// scripts/seedAdmin.js - Script to create initial admin user
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import readline from 'readline';

dotenv.config();

const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true }
}, { timestamps: true });

const Admin = mongoose.model('Admin', adminSchema);

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const question = (query) => new Promise((resolve) => rl.question(query, resolve));

async function seedAdmin() {
  try {
    console.log('🔌 Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/rightyway-aso-oke');
    console.log('✅ Connected to MongoDB\n');

    console.log('=== Create Admin User ===\n');

    const username = await question('Enter admin username: ');
    const email = await question('Enter admin email: ');
    const password = await question('Enter admin password: ');

    if (!username || !email || !password) {
      console.error('❌ All fields are required!');
      process.exit(1);
    }

    // Check if admin already exists
    const existingAdmin = await Admin.findOne({ username });
    if (existingAdmin) {
      console.log(`\n⚠️  Admin with username "${username}" already exists!`);
      const overwrite = await question('Do you want to update the password? (yes/no): ');
      
      if (overwrite.toLowerCase() === 'yes' || overwrite.toLowerCase() === 'y') {
        const hashedPassword = await bcrypt.hash(password, 10);
        existingAdmin.password = hashedPassword;
        existingAdmin.email = email;
        await existingAdmin.save();
        console.log('\n✅ Admin password updated successfully!');
      } else {
        console.log('\n❌ Operation cancelled.');
      }
    } else {
      // Create new admin
      const hashedPassword = await bcrypt.hash(password, 10);
      const admin = new Admin({
        username,
        password: hashedPassword,
        email
      });
      await admin.save();
      console.log('\n✅ Admin user created successfully!');
    }

    console.log('\n📋 Admin Details:');
    console.log(`   Username: ${username}`);
    console.log(`   Email: ${email}`);
    console.log('\n🔐 You can now login with these credentials.\n');

    rl.close();
    process.exit(0);
  } catch (error) {
    console.error('❌ Error:', error.message);
    rl.close();
    process.exit(1);
  }
}

seedAdmin();
