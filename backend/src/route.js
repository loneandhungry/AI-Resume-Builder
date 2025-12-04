import express from "express";
import { passwordSchema, schema } from "./zod.js";
import { personLogin, person } from "./mongoose.js"; 
import mongoose from "mongoose"
import dotenv from "dotenv"
import { generateBcrypt } from "./control.js";
dotenv.config({path: "../.env.local"});

import bcrypt from "bcrypt"


const route = express.Router();

route.get("/",(req,res)=>{
    res.send("workingg");
})


route.post("/build",async(req,res)=>{
    const parsed = schema.safeParse(req.body);
    if(!parsed.success){
        console.log(parsed.error);      // safeParse never throws errors. Instead it returns back an object, like parsed.error.errors
        return res.status(400).json({
            message : "Please enter all the required fields."
        })
    }
   const data = parsed.data;
    try {
        const user = new person(data);
    await user.save();     //Remember to await saving user data.
      res.json({ msg : "Your details have been saved successfully!!"});
      console.log("Resume details saved!!");
  
} catch(err){
 console.log(err);   //Variable name is err not error.message
 res.json("Error in saving your details.");
}
})


route.post("/signup",async(req,res)=>{
    const parsed = passwordSchema.safeParse(req.body); //safeParse is synchronous. No need for "await".
    if(!parsed.success){
        console.log(`${parsed.error.errors}`);
        return res.json({
            error : `${parsed.error.errors.map(e=>e.message)}`
        })
    }
    const password = req.body.password;
    const username = req.body.username;
    const existingUser = await personLogin.findOne({username: username}); //dont just write "username" here.
    //  U need to put in an object, not a string.
    if(existingUser){
        return res.json("This usename already exists!!");
    }
    try{
        const hashedpswd = await generateBcrypt(password); // this returns a promise
       // console.log(hashedpswd);
        const user = new personLogin({
            username: username,
            password: hashedpswd
        });
        
        await user.save();
        res.json({
            msg : "Your username and password is saved."
        })
        console.log("Username and password saved!");
        alert("Thank you for signing up!"); //
    } catch{
       res.json({
        error: "Not able to save the password and username(parsing done)."
       })
       console.log(err);
    }
})


export default route;


route.post("/signin",async(req,res)=>{
    const username = req.body.username;
    const password = req.body.password;

    const login = await personLogin.findOne({username: username});
    if(!login){
        return res.json({
            msg : "This username does not exist. Sign up first!"
        })
    }
    try{
    const check = bcrypt.compareSync(password, login.password);
    console.log(check);
    if(check){
      console.log("Login done!");
       return res.json({msg : "Successful Login!"})
    } else {
        return res.json({msg : "Wrong password. Please contact the developer."})
    }
} catch(err){
    res.json("Not able to signin!");
    console.log(err);
}
})