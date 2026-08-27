const bcrypt = require('bcrypt');
const dns = require('dns');
// Reddit wali DNS override trick (Cloudflare & Google Public DNS)
dns.setServers(['1.1.1.1', '8.8.8.8']);
dns.setDefaultResultOrder('ipv4first');

const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session'); // Session package added
const os = require('os');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.use(express.static('public'));

// Session Middleware (Admin & Customer authentication secure rakhne ke liye)
app.use(session({
    secret: 'tiffindose_super_secret_key_123',
    resave: false,
    saveUninitialized: false,
}));

// --- Database Connection (Optimized with DNS Override) ---
async function connectDB() {
    try {
        console.log('Attempting to connect to MongoDB Atlas...');
        await mongoose.connect(process.env.MONGO_URI, {
            family: 4,
            serverSelectionTimeoutMS: 5000
        });
        console.log('Connected to MongoDB Atlas 🚀');
    } catch (err) {
        console.error('MongoDB Connection Error:', err.message);
        console.log('⚠️ Server is running, but database is not connected due to network/firewall restrictions.');
    }
}

connectDB();

// --- Database Schema & Model (User) ---
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['customer', 'admin'], default: 'customer' },
    isMealPaused: { type: Boolean, default: false },
    address: { type: String, default: 'Not Provided' }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// --- Routes ---

// 1. Home / Landing Page (Signup)
app.get('/', (req, res) => {
    res.render('index');
});

// 2. Render Login Page
app.get('/login', (req, res) => {
    res.render('login');
});

// 3. Handle User Registration (Signup) - WITH BCRYPT PASSWORD HASHING
app.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        
        if (mongoose.connection.readyState !== 1) {
            return res.status(500).send("Database is not connected! <a href='/'>Go Back</a>");
        }

        const existingUser = await User.findOne({ email: email });
        if (existingUser) {
            return res.send("User with this email already exists! <a href='/'>Try Again</a>");
        }

        // Password ko encrypt (hash) kar rahe hain security ke liye
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            name,
            email,
            password: hashedPassword, // Plain password ki jagah hashed password save hoga
            role: 'customer',
            isMealPaused: false,
            address: 'Not Provided'
        });

        await newUser.save();
        
        // Registration ke baad session set karke direct dashboard bhejo
        req.session.userId = newUser._id;
        res.redirect(`/dashboard/${newUser._id}`);
    } catch (error) {
        console.error(error);
        res.status(500).send("Error registering user.");
    }
});

// 4. Handle Login Form Submission - WITH BCRYPT PASSWORD CHECK & SESSION
app.post('/login', async (req, res) => {
    try {
        if (mongoose.connection.readyState !== 1) {
            return res.status(500).send("Database is not connected! <a href='/login'>Go Back</a>");
        }

        const { email, password } = req.body;
        const user = await User.findOne({ email });
        
        // Check karo user exist karta hai aur bcrypt.compare se password match ho raha hai ya nahi
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.send("<script>alert('Invalid Email or Password!'); window.location.href='/login';</script>");
        }

        if (user.role === 'admin') {
            req.session.isAdminLoggedIn = true;
            res.redirect('/admin');
        } else {
            // Customer ke liye session ID set kar di
            req.session.userId = user._id;
            res.redirect(`/dashboard/${user._id}`);
        }
    } catch (error) {
        console.error(error);
        res.status(500).send("Server Error during login");
    }
});

// --- ADMIN AUTHENTICATION ROUTES ---

app.get('/admin-login', (req, res) => {
    res.render('admin-login', { error: null });
});

app.post('/admin-login', (req, res) => {
    const { username, password } = req.body;

    const ADMIN_USER = "admin";
    const ADMIN_PASS = "tiffindose123";

    if (username === ADMIN_USER && password === ADMIN_PASS) {
        req.session.isAdminLoggedIn = true;
        res.redirect('/admin');
    } else {
        res.render('admin-login', { error: "Invalid Admin Username or Password!" });
    }
});

app.get('/admin-logout', (req, res) => {
    req.session.isAdminLoggedIn = false;
    res.redirect('/admin-login');
});

// 5. Customer Dashboard Route - SECURED (Bina login ya doosre ki ID kholna block)
app.get('/dashboard/:id', async (req, res) => {
    if (!req.session.userId || req.session.userId.toString() !== req.params.id) {
        return res.redirect('/login');
    }

    try {
        if (mongoose.connection.readyState !== 1) {
            return res.status(500).send("Database is not connected!");
        }
        const user = await User.findById(req.params.id);
        if (!user) return res.redirect('/login');
        
        res.render('dashboard', { user });
    } catch (error) {
        res.status(500).send("Error fetching dashboard.");
    }
});

// 6. Toggle Meal Pause/Resume Route - SECURED
app.post('/toggle-meal/:id', async (req, res) => {
    if (!req.session.userId || req.session.userId.toString() !== req.params.id) {
        return res.redirect('/login');
    }

    try {
        if (mongoose.connection.readyState !== 1) {
            return res.status(500).send("Database is not connected!");
        }
        const user = await User.findById(req.params.id);
        if (user) {
            user.isMealPaused = !user.isMealPaused;
            await user.save();
        }
        res.redirect(`/dashboard/${req.params.id}`);
    } catch (error) {
        res.status(500).send("Error updating meal status.");
    }
});

// 7. Render Settings Page - SECURED
app.get('/settings/:id', async (req, res) => {
    if (!req.session.userId || req.session.userId.toString() !== req.params.id) {
        return res.redirect('/login');
    }

    try {
        if (mongoose.connection.readyState !== 1) {
            return res.status(500).send("Database is not connected!");
        }
        const user = await User.findById(req.params.id);
        if (!user) return res.redirect('/login');
        
        res.render('settings', { user });
    } catch (error) {
        res.status(500).send("Error loading settings.");
    }
});

// 8. Handle Profile/Address Update - SECURED
app.post('/update-settings/:id', async (req, res) => {
    if (!req.session.userId || req.session.userId.toString() !== req.params.id) {
        return res.redirect('/login');
    }

    try {
        if (mongoose.connection.readyState !== 1) {
            return res.status(500).send("Database is not connected!");
        }
        const { name, address } = req.body;
        await User.findByIdAndUpdate(req.params.id, { name, address });
        res.redirect(`/dashboard/${req.params.id}`);
    } catch (error) {
        res.status(500).send("Error updating settings.");
    }
});

// 9. Logout Route (Customer) - Session destroy karega
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

// 10. Secure Admin Dashboard Route
app.get('/admin', async (req, res) => {
    if (!req.session || !req.session.isAdminLoggedIn) {
        return res.redirect('/admin-login');
    }

    try {
        if (mongoose.connection.readyState !== 1) {
            return res.status(500).send("Database is not connected!");
        }
        const customers = await User.find({ role: 'customer' }).sort({ name: 1 });
        res.render('admin', { users: customers });
    } catch (error) {
        res.status(500).send("Error fetching admin data.");
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on:`);
    console.log(`- Local:   http://localhost:${PORT}`);
    
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const net of interfaces[name]) {
            if (net.family === 'IPv4' && !net.internal) {
                console.log(`- Network: http://${net.address}:${PORT}`);
            }
        }
    }
});