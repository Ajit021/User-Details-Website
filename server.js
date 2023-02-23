require('dotenv').config();
const express = require('express')
const app = express();
const pg = require('pg')
const port = process.env.PORT || 3000;
const bcrypt = require('bcrypt')
const JWT_REFRESH_SECRET = process.env.SECRET_KEY
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path')
const fs = require('fs')





const pool = new pg.Pool({
    "host": "localhost",
    "port": 5432,
    "user":"ajit",
    "password" : "Ajit@021",
    "database" : "postgres",
    "max": 20,
    "connectionTimeoutMillis" : 0,
    "idleTimeoutMillis": 0
}) 

app.use(express.json())
app.use(cookieParser())
app.use(express.urlencoded({extended:false}))


app.get("/",(req,res)=>{

     res.sendFile(__dirname+"/index.html");
})

app.get("/register",(req,res)=>{
        res.sendFile(__dirname+"/register.html");
})


app.get("/login",(req,res)=>{
    try {
        if(req.cookies.jwt){
            const verifyuser= jwt.verify(req.cookies.jwt,JWT_REFRESH_SECRET)
            //console.log(verifyuser)
            var userHtml = fs.readFileSync(__dirname + "/update.html","utf-8")
                userHtml = userHtml.replace("%USER%", verifyuser.name);   
                res.setHeader("content-type", ["text/html"])
                res.send(userHtml)
            
           
        }
    
        else {
        res.sendFile(__dirname+"/login.html");
        }
    } catch (error) {
        res.send("Invalid Token Please Login Again")
    }
   
})


app.get("/logout",async(req,res)=>{
    try {
        if(req.cookies.jwt){
        
            jwt.verify(req.cookies.jwt,JWT_REFRESH_SECRET)
    
                 const cookietoken=req.cookies.jwt;
                 res.clearCookie('jwt')
                await pool.query("update userpool set token = NULL where token = $1", [cookietoken])
    
                 console.log("LOGOUT SUCCESSFULLY ")
                 
                 res.sendFile(__dirname+"/index.html")      
        }
        else{
            console.log("Login First")
            res.sendFile(__dirname+"/login.html")
        }
    } catch (error) {
        res.send(error)
    }
    
    
})



app.get("/update",(req,res)=>{
    if(req.cookies.jwt){
        const verifyuser= jwt.verify(req.cookies.jwt,JWT_REFRESH_SECRET)
        if(verifyuser){
            console.log(verifyuser.name)

            let userHtml = fs.readFileSync(__dirname + "/update.html","utf8")
            userHtml = userHtml.replace("%USER%", verifyuser.name);
            res.setHeader("content-type", ["text/html"])
            res.send(userHtml)
        }
    }
    else{
        res.sendFile(__dirname+"/login.html");
    }
})





app.post("/register", async (req, res) => {
        //check if user exist 
    try{
        const sql = "select emailid from userpool where emailid = $1"
        const result = await pool.query(sql,
                                 [req.body.email]);

        //console.log(result.rowCount)
        
        //if user is not there create it 
         if (result.rowCount == 0){
             
              if((req.body.password).length!=0){

                  if(req.body.password== req.body.cpassword){
                    if((req.body.phonenumber).length< 10 || (req.body.phonenumber).length> 10)
                    {
                        res.send("Phone number should be equal to 10 digits")
                    }
                    else{

                        const hash =  await bcrypt.hash(req.body.password, 10)
                      
                        await pool.query("insert into userpool (name, emailid, phonenumber,password,dob) values ($1,$2,$3,$4,$5)",
                            [req.body.name,req.body.email,req.body.phonenumber,hash,req.body.dob]);
                           

                            //cookie delete
                            const cookietoken=req.cookies.jwt;
                            res.clearCookie('jwt')
                    
                    
                            await pool.query("update userpool set token = NULL where token = $1", [cookietoken])
                            res.send({"success": "User created successfully"})
                    }
                      
                  }
                  else{
                      res.send("Password Not Matched")
                  }
              } 
            
              else{
                  res.send("Enter Password")
              }
            }

      
           
        else
            res.send({"error": "Email Already Used"})
    }
     catch(error){
        res.send("Error in Sign up Please try again")
     }
})


//LOGIN

app.post("/login", async (req, res) => {

    try {
        const sql = "select *  from userpool where emailid = $1"
    const result = await pool.query(sql,
                             [req.body.email]);

        if(result.rowCount == 1){
            const passwordmatchvar= result.rows[0].password
            const resultmatch =await bcrypt.compare(req.body.password, passwordmatchvar)
            if(resultmatch==true){
                
                //JWT TOKEN
                const payLoad = {"name": result.rows[0].name,
                "emailid": result.rows[0].emailid }

                const refreshtoken = jwt.sign(payLoad, JWT_REFRESH_SECRET , { algorithm: 'HS256'})
                
                res.cookie("jwt",refreshtoken)
                

                //save the  token in the database 
                    await pool.query("update userpool set token = $1 where emailid = $2", [refreshtoken, result.rows[0].emailid ])

                
    
                let userHtml = fs.readFileSync(__dirname + "/update.html","utf-8")
                userHtml = userHtml.replace("%USER%", result.rows[0].name);
                res.setHeader("content-type", ["text/html"])
                res.send(userHtml)
            }
                else{
                    res.send("EmailId or Password is invalid")
                }
        }
            else{
                res.send("EmailId or Password is invalid")
            }
    } catch (error) {
        res.send("Error in the Login Please Login again")
    }
    
})



//Update
app.post("/update", async (req, res) => {
    try {
        if ((req.body.phonenumber).length < 10 || (req.body.phonenumber).length > 10) {
            res.send("Phone number should be equal to 10 digits")
        }
        else {

            const verifyuser = jwt.verify(req.cookies.jwt, JWT_REFRESH_SECRET)
            console.log(req.body)
            await pool.query("update userpool set phonenumber = $1,DOB=$2 where emailid = $3", [req.body.phonenumber, req.body.dob, verifyuser.emailid])
            res.send({ "success": "User updated successfully" })
        }
    } catch (error) {
        res.send("Error in Update Please try again")
    }
    
})













    app.listen(port)