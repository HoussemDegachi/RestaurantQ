import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import dotenv from "dotenv";

dotenv.config();

export async function hashPassword(password) {
  return await bcrypt.hash(password, 12);
}

export async function verifyPassword(plainPassword, hashPassword) {
  return await bcrypt.compare(plainPassword, hashPassword);
}

export function signToken(userId, expiresIn = "24h") {
  return jwt.sign({ userId }, process.env.JWT_KEY, { expiresIn });
}

export function verifyToken(token) {
  return jwt.verify(token, process.env.JWT_KEY);
}
