import express from "express"
import mongoose from "mongoose"
import dotenv from "dotenv"
dotenv.config({path: "../.env.local"});



export const person = mongoose.model('users',  //users is the collection here
   { userID: {type : String, required : true},
     username : {type : String, required : true},
     name : {type : String, required : true},
     email: {type : String, required : true},
     phoneNumber: {type : String, required : true},

     education: [
        {
            college: String,
            degree: String,
            cg : String,
            start_year : String,
            end_year: String,
        }
     ],
     skills: [String],
     experience: [
        {
        company: String,
        role: String,
        duration: String,
        description:String,
        start_date: String,
        end_date: String
        }
     ],
     projects:[{
        title: String,
        github: String,
        techstack: String,
        description: String
     }],
     linkedin: String, 
    
}
)

export const personLogin = mongoose.model('logins', //logins is the collection here //database is specified at the end of the url
    {
    username: {type : String , required : true},
    password: {type: String, required : true }
})

