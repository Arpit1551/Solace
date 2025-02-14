const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
    username: {
        firstName: {
            type: String,
            required: true,
            minlength: [3, 'First name must be at least 3 characters long']
        },
        lastName: {
            type: String
        }
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    history:[{
        type: String,
        default: "No history"
    }],
    healthInfo:[{
        date:{
            type:Date,
            default:Date.now},
        data:{type:String}
}],
    accessToken:{
        type: String
    },
    dateOfCreation: {
        type: Date,
        default: Date.now
    }
});

userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();

    this.password = await bcrypt.hash(this.password, 10);
    next();
});

userSchema.pre('save', function(next) {
    const sevenDaysAgo = new Date();
    
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    this.healthInfo = this.healthInfo.filter(entry => entry.date >= sevenDaysAgo);
    next();
});

userSchema.methods.comparePassword = async function(givenPassword) {
    const isMatch = await bcrypt.compare(givenPassword, this.password);
    return isMatch;
};

userSchema.methods.generateToken = async function() {
    const token = jwt.sign({is:this.id}, process.env.JWT_SECRET,{expiresIn: '5h'});
    return token;
};

const User = mongoose.model('User', userSchema);
module.exports = User;