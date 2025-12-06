import express from "express";
import { passwordSchema, schema } from "./zod.js";
import { personLogin, person } from "./mongoose.js"; 
import mongoose from "mongoose"
import dotenv from "dotenv"
dotenv.config({path: "../.env.local"});


import { generateBcrypt, verify } from "./control.js";
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"


const route = express.Router();

route.get("/",(req,res)=>{
    res.send("workingg");
})

route.post("/build",verify,async(req,res)=>{
    const parsed = schema.safeParse(req.body);
    if(!parsed.success){
        console.log(parsed.error);      // safeParse never throws errors. Instead it returns back an object, like parsed.error.errors
        return res.status(400).json({
            message : "Please enter all the required fields."
        })
    }
   const data = parsed.data;
    try {
        console.log(req.user.userID);
        console.log(req.user.username);
        const user = new person({username: req.user.username,userID: req.user.userID, ...data}); // three dots : SPREAD OPERATOR
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
        alert("The username should have atleast 4 characters and the password should have atleast 6 !");
        return res.json({
            error : `The username should have atleast 4 characters and the password should have atleast 6 !`
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
 
    if(check){
      console.log("Login done!");
      const userID = login._id;
      try{
      console.log(login._id);
      } catch(err){
      console.log("Not able to log in the user id");
      }
      const token = jwt.sign({username : username, userID : userID}, process.env.JWTSECRET, {expiresIn : "2d"});  ///creating token
      
      //cookie
      
      res.cookie("authToken",token,{  //name,value
        httpOnly: true,  //	Flags the cookie to be accessible only by the web server.
       // secure: true,  //marks the cookie to be used with https only
        sameSite: "strict", //Value of the “SameSite” Set-Cookie attribute
        maxAge: 2*24*60*60*1000
      })
      
       return res.json({msg : "Successful Login!"})
    } else {
        return res.json({msg : "Wrong password. Please contact the developer."})
    }



} catch(err){
    res.json("Not able to signin!");
    console.log(err);
}
})




export default route;