import bcrypt from "bcrypt"

export async function generateBcrypt(password){ //for hashing we are using bcrypt library
   const pswd = await bcrypt.hash(password,10);  // 10 is the salt (number of rounds)
   console.log("Bycrypting done");
   return pswd;
}

