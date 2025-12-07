import express from "express";
import { passwordSchema, schema } from "./zod.js";
import { personLogin, person } from "./mongoose.js"; 
import mongoose from "mongoose"
import dotenv from "dotenv"
dotenv.config({path: "../.env.local"});


import { generateBcrypt, verify } from "./control.js";
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import { httpUrl } from "zod";


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


route.get("/resume/all",verify, async(req,res)=>{
    const userID = req.user.userID;
 
    try{
    const resume = await person.find({userID : userID});  ///dont forget to await here
    res.json(resume);
    } catch(err){
        console.log(err);
        return res.send("Not able to fetch your resumes");
    }
})


route.get("/resume/:id", verify, async(req,res)=>{
    const resumeID = req.params.id;
    try{
       
    const resume = await person.find({_id: resumeID});
    if(resume.userID === req.user.userID){    
     console.log("Matched!")
     res.json(resume);
    
    }
    else{
        return res.json({
           msg:  "Please do not try to open someone else's resume."   //DONT TRY OPENING SOMEONE ELSE'S RESUME
        })
    }
    } catch(err){
        console.log(err);
        return res.send("Cannot find this resumeID.Please put in the correct one.");
    }
})

route.put("/resume/edit/:id", verify, async(req,res)=>{
    const resumeID = req.params.id;
    const edit = req.body;

    const search = await person.findById(resumeID);
    if(!search){return res.send("This resumeID does not exist.")}

   if ("userID" in edit) {                //IMPORTANT //check whether the user is trying to change the userID 
    return res.status(400).send("You are not allowed to change userID.");
}
    delete edit.userID;
       
    try{
    if(search.userID.toString() === req.user.userID.toString()){  
         
     console.log("Matched!")
     const success = await person.findByIdAndUpdate(resumeID, edit, { new: true });
      res.json({
        msg : "Your resume has been updated."
     })
     if(!success){
        return res.send("Resume not found");
     }
    }else{
        return res.send("Don't try to access other people's resume please.")
    }
   }catch(err){
    console.log(err);
      return res.send("Cannot find your resume.")
    }
})

route.delete("/resume/delete/:id",verify,async (req,res)=>{
    const resumeID = req.params.id;
    let resume;
    try{
     resume = await person.findById(resumeID);
    } catch(err){
        return res.send("Incorrect resumeID");
    }
    if(!resume){
        return res.send("This resumeID does not exist.");
    }
    if(req.user.userID !== resume.userID.toString() ){
        return res.send("Please do not try to access other people's resumes.")
    }
    try{
        const success = await person.findByIdAndDelete(resumeID);
        if(success){
        return res.send("This resume has been deleted.");
        }
        else{
            res.send("Not able to delete this resume")
        }
    } catch(err){
        console.log(err);
        return res.send("Not able to delete this resume")
    }
})



route.delete("/user/delete/:id", verify , async(req,res)=>{
    const userID = req.params.id;
    if(req.user.userID !== userID ){
        return res.send("Please do not try to access other people's accounts.")
    }
    let user;
    try{
     user = await personLogin.findByIdAndDelete(userID);
    } catch(err){
        return res.send("Incorrect userID");
    }
     if(!user){
        return res.send("This userID does not exist.");
    }
    
    try {
        await person.deleteMany({userID : userID});      //deleteMany
        res.clearCookie("authToken" , {
            httpOnly: true,
            sameSite: "strict"
        })
        res.send("Your acconut has been completely deleted successfully!!")
    } catch(err){
        console.log(err);
        return res.status(500).send("Not able to delete your account.");
    }
})

route.post("/signout",verify,(req,res)=>{
        res.clearCookie("authToken",{
            httpOnly : true,
            sameSite : "strict"
    })
     return res.json({ msg : "You have successfullly signed out."})
    })
   
export default route;