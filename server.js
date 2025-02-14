const express = require('express');
const app = express();
const path = require('path');
const cors = require('cors');
const { body } = require('express-validator');
// const userController = require('./controllers/userController');
const User = require('./models/userModel');
const cookieParser = require('cookie-parser');
const passport = require('passport');
const session = require('express-session');
const googleStrategy = require('passport-google-oauth20').Strategy;


require('dotenv').config();

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('views', path.join(__dirname, 'views'));
app.use(cors());
app.use(cookieParser());

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new googleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
    try {
        // Here, you could find or create a user in your database based on the Google profile
        let userdata = await User.findOne({ email: profile.emails[0].value });

        if (!userdata) {
            // If the user doesn't exist, create one
            userdata = new User.create({
                username: {
                    firstName: profile.name.givenName,
                    lastName: profile.name.familyName
                },
                email: profile.emails[0].value,
                accessToken: token,
            });
            await userdata.save();
        }

        done(null, userdata);
    } catch (err) {
        done(err);
    }
}));

passport.serializeUser((user, done) => { done(null, user) });
passport.deserializeUser((user, done) => { done(null, user) });


app.get('/', (req, res) => {
    res.render('index');
});

app.get('/Solance', (req, res) => {
    res.render('landing');
});

app.get('/ChatBot', (req, res) => {
    res.render('chatBot');
});

app.get('/Dashboard', async (req, res) => {
    // const token = req.cookies.token;
    // if (!token) {
    //     res.redirect('/login');
    //     return;
    // }
    // const checkToken = jwt.verify(token, process.env.JWT_SECRET);
    // if (!checkToken) {
    //     res.redirect('/login');
    //     return;
    // }

    // const user = await usermodel.findOne({ _id: checkToken.id });
    res.render('dashboard');
});

const { GoogleGenerativeAI } = require('@google/generative-ai');

const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

const MAX_RETRIES = 3; // Maximum number of retries
const RETRY_DELAY = 1000; // Delay between retries in milliseconds

async function sendMessageWithRetry(chat, msg, retries = MAX_RETRIES) {
    try {
        const result = await chat.sendMessage(msg);
        return result;
    } catch (error) {
        if (error.status === 503 && retries > 0) {
            console.log(`Retrying... Attempts left: ${retries}`);
            await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
            return sendMessageWithRetry(chat, msg, retries - 1);
        } else {
            throw error; // Re-throw the error if retries are exhausted
        }
    }
}


app.post("/chat", async (req, res) => {
    const chatHistory = req.body.history || [];
    const msg = req.body.chat;

    const chat = model.startChat({
        history: chatHistory
    });

    try {
        const result = await sendMessageWithRetry(chat, msg);
        const response = await result.response;
        const text = response.text();
        res.send({ text });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).send({ error: 'Failed to process the request. Please try again later.' });
    }
});


app.post("/stream", async (req, res) => {
    const chatHistory = req.body.history || [];
    const msg = req.body.chat;

    const chat = model.startChat({
        history: chatHistory
    });

    try {
        const result = await sendMessageWithRetry(chat, msg);
        for await (const chunk of result.stream) {
            const chunkText = chunk.text();
            res.write(chunkText);
        }
        res.end();
    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('Failed to process the request. Please try again later.');
    }
});

app.get('/register', (req,res)=>{
    res.render("register")
})

app.post("/register", [
    body('username.firstname')
        .isLength({ min: 3 })
        .withMessage('Firstname must be at least 3 characters long')
        .matches(/^[A-Za-z]+$/)
        .withMessage('Firstname should contain only letters'),

    body('username.lastname')
        .isLength({ min: 3 })
        .withMessage('Lastname must be at least 3 characters long')
        .matches(/^[A-Za-z]+$/)
        .withMessage('Lastname should contain only letters'),

    body('email')
        .isEmail()
        .withMessage('Invalid email address'),

    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long')
    //   .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/)
    //   .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty) { return res.status(400).json({ errors: errors.array() }) };

    const { username, email, password } = await req.body;

    const checkUser = await usermodel.findOne({ email });
    if (checkUser) {
        return res.status(400).json({ msg: 'User already exists' });
    }

    const newUser = new usermodel.create({ username, email, password });
    newUser.save();

    const token = await newUser.generateToken();
    newUser.accessToken = token;
    newUser.save();
    res.cookie('token', token, { httpOnly: true });

    res.redirect('/Dashboard');
});

app.get('/login', (req,res)=>{
    res.render('login')
});

app.post("/login", [
    body('email')
        .isEmail()
        .withMessage('Invalid email address'),

    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long')
    //   .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/)
    //   .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
], async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty) { return res.status(400).json({ errors: errors.array() }) };

        const { email, password } = req.body;

        const findUser = await usermodel.findOne({ email });
        if (!findUser) {
            return res.status(400).json({ msg: 'No user found' });
        }

        const checkPassword = await findUser.comparePassword(password);
        if (!checkPassword) {
            return res.status(400).json({ msg: 'Password incorrect' });
        }

        const token = await findUser.generateToken();
        findUser.accessToken = token;
        findUser.save();
        res.cookie('token', token, { httpOnly: true });

        redirect('/Dashboard');
    });

// app.post("/googleRegister", userController.googleRegister);

app.listen(3000, () => {
    console.log('Server is running on http://localhost:3000');
});