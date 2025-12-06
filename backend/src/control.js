import bcrypt from "bcrypt"
import express from "express"
import dotenv from "dotenv"
dotenv.config({path: "../.env.local"})
import jwt from "jsonwebtoken"

export async function generateBcrypt(password){ //for hashing we are using bcrypt library
   const pswd = await bcrypt.hash(password,10);  // 10 is the salt (number of rounds)
   console.log("Bycrypting done");
   return pswd;
}


export async function  verify(req,res,next) {

    const token = req.cookies?.authToken;   //is the name of the cookies authToken??

    if(!token) return res.json("Token Missing. Please login again.");
    try{
    const decoded = jwt.verify(token, process.env.JWTSECRET);
    req.user = decoded;  //save the user data , who is logged in 
     next();
    } catch(err){
        console.log(err);
        return res.json("Wrong token sent")
    }
}
