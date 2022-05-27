// Libraries and Packages
import express from "express";
import dotenv from "dotenv/config";
import bcrypt from "bcrypt";
import Token from "jsonwebtoken";
import { validationResult } from "express-validator";

// Data-Base Models/Collections
import User from "../models/userSchema.js";

//  Middleware
import { loginValidate, signupValidate } from "../middleware/validation.js";
import { authenticateUser } from "../middleware/authenticateUser.js";

// Express Routes
const router = express.Router();
const error = 401;

//Routes
router.get("/", authenticateUser, async (req, res) => {
  const user = await User.findOne({ _id: req.body.id });

  if (user) {
    return res.status(200).send({
      verified: true,
      username: user.username,
      tasks: user.tasks,
    });
  }
});

router.post("/login", loginValidate, async (req, res) => {
  
  const validateErr = validationResult(req);
  if (!validateErr.isEmpty()) {
    return res.status(error).json({ errors: validateErr[0] });
  }
  const username = req.body.username;
  const password = req.body.password;

  const user = await User.findOne({ username: username });

  // check if the username does exist in the database
  if (!user) {
    return res.status(error).send({
      error: `no user is found with this username ${username}`,
    });
  }
  bcrypt.compare(password, user.password, function (err, result) {
    if (err) {
      return res.status(error).send({ error: "error, please try again later" });
    }
    if (result !== true) {
      return res.status(error).send({
        error: "password is wrong, please try again",
      });
    }
    // generate token and add it to headers response
    try {
      const token = getToken(user._id);
      return setTimeout(
        () =>
          res
            .status(200)
            .set({
              "Access-Control-Expose-Headers": "Authorization",
              Authorization: "Bearer " + token,
            })
            .json({
              username: user.username,
              tasks: user.tasks,
              mode: user.mode,
            }),
        2000
      );
    } catch (err) {
      console.error(err);
    }
  });
});

router.post("/signup", loginValidate, signupValidate, async (req, res) => {

  console.log('84');
  const validateErr = validationResult(req);
  if (!validateErr.isEmpty()) {
    return res.status(error).json({ error: error });
  }
  console.log('89 user pass validate');
  const username = req.body.username;
  const password = req.body.password;
  const repeat_password = req.body.repeat_password;

  if (repeat_password !== password) {
    return res.status(error).send({ error: "passwords doesn't match" });
  }

  // hash the password
  const hashedPassword = hashPassword(password);
  if (!hashedPassword) {
    return res.status(error).send({ error: "Error, please try again later" });
  }

  console.log('120 password is hashed ');
  // store the user with the hashed password in the database
  const newUser = await new User({
    username: username,
    password: hashedPassword,
  });
  console.log('110 user is created ');
  newUser.save((err) => {
    if (err) {

      console.log(' line 113',err);
      return res.status(error).send({ errors: [err.message] });
    }
    console.log('115 user is saved ');
    // generate token and add it to headers response
    try {
      const token = getToken(newUser._id, username);

      console.log('120 token is generated');
      return res
        .set({
          "Access-Control-Expose-Headers": "Authorization",
          Authorization: "Bearer " + token,
        })
        .send({
          username: newUser.username,
        });
    } catch (err) {
      return res.status(error).send({ error: err });
    }
  });
});

router.put("/update/mode", async (req, res) => {
  const mode = req.body.mode;

  return await User.updateOne(
    { _id: req.body.id },
    {
      $set: { mode: mode },
      $currentDate: { lastModified: true },
    }
  )
    .then(() => {
      res.status(200).send("mode changed");
    })
    .catch((err) => {
      res.status(error).send({
        error: "couldn't update the mode, please try again later",
      });
    });
});

export default router;

// create token for the user
function getToken(id) {
  return Token.sign({ id }, process.env.TOKEN_KEY, {
    expiresIn: "7d",
  });
}

function hashPassword(password) {
  const hash = bcrypt.hashSync(password, 10);
  return hash;
}
