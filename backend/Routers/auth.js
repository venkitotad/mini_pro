import express from "express";
 import { registerUser } from "../Controllers/RegisterController";
 import { loginUser } from "../Controllers/LoginController";

const router = express.Router();

router.post("/register", registerUser);
router.post("/login", loginUser);

export default router;
