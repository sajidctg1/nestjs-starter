import { configDotenv } from "dotenv";
import { z } from "zod";

configDotenv();

const schema = z.object({
  APP_ENV: z.enum(["development", "staging", "test", "production"]),
  APP_PORT: z.coerce.number(),
  APP_NAME: z.string(),
  APP_URL: z.string().url(),
  CLIENT_URL: z.string().url(),
  ALLOWED_ORIGINS: z.string().optional(),
  // ------------------------ auth
  COOKIE_SECRET: z.string(),
  CONFIRMATION_TOKEN_SECRET: z.string(),
  CONFIRMATION_TOKEN_EXPIRES: z.coerce.number(),
  BCRYPT_SALT: z.coerce.number(),
  // jwt
  JWT_ALGORITHM: z.string().default("HS256"),
  JWT_ACCESS_TOKEN_SECRET: z.string(),
  JWT_ACCESS_TOKEN_EXPIRES: z.coerce.number(),
  JWT_REFRESH_TOKEN_SECRET: z.string(),
  JWT_REFRESH_TOKEN_EXPIRES: z.coerce.number(),
  // oauth
  GOOGLE_CLIENT_ID: z.string(),
  GOOGLE_CLIENT_SECRET: z.string(),
  GOOGLE_CALLBACK_URL: z.string(),
  // ------------------------ db
  DB_DRIVER: z.enum(["mysql", "mariadb", "postgres"]),
  DB_HOST: z.string(),
  DB_PORT: z.coerce.number(),
  DB_NAME: z.string(),
  DB_USER: z.string(),
  DB_PASSWORD: z.string(),
  // redis
  //   REDIS_URI: z.string().url(),
  //   REDIS_HOST: z.string(),
  //   REDIS_TTL: z.coerce.number().min(1),
  //   REDIS_PORT: z.coerce.number(),
  //   REDIS_USERNAME: z.string(),
  //   REDIS_PASSWORD: z.string(),
  // ------------------------ email
  MAIL_HOST: z.string(),
  MAIL_PORT: z.coerce.number(),
  MAIL_USERNAME: z.string(),
  MAIL_PASSWORD: z.string(),
  MAIL_ENCRYPTION: z.string(),
  SUPPORT_MAIL_ADDRESS: z.string().email(),
  MAIL_FROM_ADDRESS: z.string().email(),
  MAIL_FROM_NAME: z.string(),
  // ------------------------ storage
  FILESYSTEM_DISK: z.enum(["public", "s3"]).default("public"),
  AWS_ACCESS_KEY_ID: z.string().optional(),
  AWS_SECRET_ACCESS_KEY: z.string().optional(),
  AWS_DEFAULT_REGION: z.string().optional(),
  AWS_BUCKET: z.string().optional(),
  AWS_URL: z.string().optional(),
});

export const env = schema.parse(process.env);
