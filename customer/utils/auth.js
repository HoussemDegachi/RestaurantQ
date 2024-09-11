import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

export async function hashPassword(password) {
  return await bcrypt.hash(password, 12);
}

export async function verifyPassword(plainPassword, hashPassword) {
  return await bcrypt.compare(plainPassword, hashPassword);
}
