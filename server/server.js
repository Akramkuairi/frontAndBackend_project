// Libraries and Packages
import express from "express";
import dotenv from "dotenv/config";
import mongoose from "mongoose";
import cors from "cors";

// Routes
import UserRoute from "./routes/user.js";
import TaskRouter from "./routes/tasks.js";

// middleware
import { authenticateUser } from "./middleware/authenticateUser.js";


// const variable
const app = express();
const port = process.env.PORT || 3000;

const corsConfig = {
  origin: "http://localhost:3000",
  credentials: true,
};
console.log("line 22",process.env.DATABASE_URL);
// connect to mongodb
mongoose
  .connect(process.env.DATABASE_URL)
  .then(() => console.log("MongoDB is connected"))
  .catch((err) => console.error(err));

// express middleware
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use("/", cors(corsConfig));
app.use("/user", UserRoute);
app.use("/tasks", authenticateUser, TaskRouter);
app.use("/", authenticateUser);

app.get("/", (req, res) => {
  return res.send("Hello, world");
});

app.listen(port, () => console.log(`app is running on port ${port}`));
