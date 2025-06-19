import express from "express";
import ViteExpress from "vite-express";
import dotenv from "dotenv";
import pool from "./db/client.js";
import PgSession from "connect-pg-simple";
import session from "express-session";
import passport from "passport";
import LocalStrategy from "passport-local";
import bcrypt from "bcrypt";

dotenv.config();

const PgSessionStore = PgSession(session);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    store: new PgSessionStore({ pool }),
    secret: process.env.SES_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 1 day
      httpOnly: true,
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new LocalStrategy(async (username, password, done) => {
    console.log("LocalStrategy called", username, password);
    try {
      const user = await findUserByUsername(username);
      console.log("A", user);
      if (!user) {
        const user = await registerUser(username, password);
        console.log("B", user);
        return done(null, user);
      }
      const valid = await bcrypt.compare(password, user.password);
      console.log("C", valid);
      if (!valid)
        return done(null, false, {
          message: "ユーザ名またはパスワードが間違っています",
        });
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);
passport.serializeUser((user, done) => {
  done(null, user.id);
});
passport.deserializeUser(async (id, done) => {
  try {
    const user = await findUserById(id);
    done(null, user || false);
  } catch (err) {
    done(err);
  }
});

const registerUser = async (username, password) => {
  const res = await pool.query(
    "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *",
    [username, password]
  );
  console.log(res.rows[0]);
  return res.rows[0];
};

const findUserByUsername = async (username) => {
  const res = await pool.query("SELECT * FROM users WHERE username = $1", [
    username,
  ]);
  return res.rows[0];
};
const findUserById = async (id) => {
  const res = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
  return res.rows[0];
};

app.use((req, res, next) => {
  if (
    [
      "/",
      "/login",
      "/@vite/client",
      "/favicon.ico",
      "/node_modules/vite/dist/client/env.mjs",
    ].includes(req.path)
  ) {
    return next();
  }
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).send("認証されていません");
});

// app.post("/login", passport.authenticate("local"), (req, res) => {
//   res.send("ログイン成功");
// });
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/hello",
    failureRedirect: "/",
  })
);

app.get("/hello", (req, res) => {
  res.send("Hello Vite!");
});

ViteExpress.listen(app, process.env.APP_PORT, () =>
  console.log(`Server is listening on port ${process.env.APP_PORT}...`)
);
