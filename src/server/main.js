import express from "express";
import ViteExpress from "vite-express";
import dotenv from "dotenv";
import pool from "./db/client.js";
import PgSession from "connect-pg-simple";
import session from "express-session";
import passport from "passport";
import LocalStrategy from "passport-local";
import bcrypt from "bcrypt";
import flash from "connect-flash";

dotenv.config();

const PgSessionStore = PgSession(session);

const app = express();
app.set("view engine", "ejs");
app.set("views", "src/server/views");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/", express.static("public"));
app.use(flash());
app.use(
  session({
    store: new PgSessionStore({
      pool: pool,
      createTableIfMissing: true, // Automatically create the session table if it doesn't exist
    }),
    secret: process.env.SES_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      //   maxAge: 1000 * 60 * 60 * 24, // 1 day
      httpOnly: true,
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await findUserByUsername(username);
      if (!user) {
        console.log("User not found, registering new user");
        const user = await registerUser(username, password);
        return done(null, user);
      }
      console.log("User found, checking password");
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) {
        console.log("Invalid password, authentication failed");
        return done(null, false, {
          message: "ユーザ名またはパスワードが間違っています",
        });
      }
      console.log("Password is valid, authentication successful");
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
  const hashedPswd = await bcrypt.hash(password, 10);
  const res = await pool.query(
    "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *",
    [username, hashedPswd]
  );
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
  res.redirect("/401.html");
});
app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    res.redirect("/hello");
  } else {
    res.render("login", { error: req.flash("error") });
  }
});
app.get("/hello", (req, res) => {
  res.render("hello", {});
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/hello",
    failureRedirect: "/",
    failureFlash: true,
  })
);
app.post("/logout", (req, res) => {
  req.logout((err) => {
    if (err) return res.status(500).send("Logout failed");
    res.sendStatus(200);
  });
});

ViteExpress.listen(app, process.env.APP_PORT, () =>
  console.log(`Server is listening on port ${process.env.APP_PORT}...`)
);
