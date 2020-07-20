const express = require("express");
const chalk = require("chalk");
const mongoose = require("mongoose");
const db = require("./DB/db");
const config = require("config");

const userController = require("./controller/userController");

const app = express();

//Allow Cors
app.use(function (req, res, next) {
  res.header("Access-Control-Allow-Origin", "*"); // update to match the domain you will make the request from
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE"); // update to match the domain you will make the request from
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );
  next();
});

//Parse JSON
app.use(express.json());

//check whether jwtkey is set or not
if (!config.get("jwtPrivateKey")) {
  console.error("FATAL ERROR: jwtPrivateKey is not defined");
  process.exit(1);
}

//fetch db connection data and connect to mongodb
const { host, database, port } = db;

//Set up default mongoose connection
var mongoDB = "mongodb://localhost:27017/Authentication";

console.log(mongoDB);

//mongoose.set("useNewUrlParser", true);
mongoose.set("useFindAndModify", false);
mongoose.set("useCreateIndex", true);
mongoose.set("useUnifiedTopology", true);
//var mongoDB = `mongodb://${host}:${port}/${database}`;
mongoose.connect(mongoDB, { useNewUrlParser: true });

mongoose.Promise = global.Promise;

//Get the default connection
var dba = mongoose.connection;

dba.on(
  "connected",
  console.log.bind(console, `${chalk.green("MongoDB connection done")}`)
);

//Bind connection to error event (to get notification of connection errors)
dba.on("error", console.error.bind(console, "MongoDB connection error:"));

//Setting Routes
app.use("/user", userController);

//port setting and start server
const Port = 9889; //process.env.PORT || 3000;
app.listen(Port, () => {
  console.log(`Server running on port ${chalk.green(Port)}`);
});
