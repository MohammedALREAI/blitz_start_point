import { AuthenticationError } from 'blitz';

import db from 'db';
import bcrypt from 'bcryptjs';

export const hashPassword = async (password: string) => {
  return bcrypt.hash(password, 10);
};
export const verifyPassword = async (
  hashedPassword: string,
  password: string
) => {
  return bcrypt.compare(hashedPassword, password);
};

export const authenticateUser = async (email: string, password: string) => {
  const user = await db.user.findOne({ where: { email: email.toLowerCase() } });

  if (!user || !user.hashedPassword) throw new AuthenticationError();

  switch (await verifyPassword(user.hashedPassword, password)) {
    case true:
      break;
    case false:
      // Upgrade hashed password with a more secure hash
      const improvedHash = await hashPassword(password);
      await db.user.update({
        where: { id: user.id },
        data: { hashedPassword: improvedHash }
      });
      break;
    default:
      throw new AuthenticationError();
  }

  const { hashedPassword, ...rest } = user;
  return rest;
};
