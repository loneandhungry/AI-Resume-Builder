import express from "express";
const app = express();
app.use(express.json());

import mongoose from "mongoose";
import route from "./route.js";
import dotenv from "dotenv";
dotenv.config(); 
const port = process.env.PORT;
const WEB = process.env.MONGODB_URL;

mongoose.connect(WEB)
.then(()=> console.log("Database connected!"))
.catch((err)=> console.log(err));  //Remember that .then() ke saath .catch() rehta hai
 
app.use("/", route);

app.listen(port, ()=>{
    console.log(`Sever started on port ${port}`);
})



