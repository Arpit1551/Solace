const express = require('express');
const {validationResult} = require('express-validator');
const usermodel = require('../models/userModel');

const app = express();


app.post("/userLogin", async (req,res)=>{
    const errors = validationResult(req);
    if(!errors.isEmpty){return res.status(400).json({errors: errors.array()})};

    const {email, password} = req.body;

    const findUser = await usermodel.findOne({email});
    if(!findUser){
        return res.status(400).json({msg: 'No user found'});
    }

    const checkPassword = await findUser.comparePassword(password);
    if(!checkPassword){
        return res.status(400).json({msg: 'Password incorrect'});
    }

    const token = await findUser.generateToken();
    findUser.accessToken = token;
    findUser.save();
    res.cookie('token', token, {httpOnly: true});

    redirect('/Dashboard');
});

// app.post('googleRegister', async (req,res)=>{
    
// }); 
