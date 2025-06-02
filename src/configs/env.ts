import { configDotenv } from "dotenv";
import { z } from "zod";

configDotenv();

const schema = z.object({
  NODE_ENV: z.enum(["development", "staging", "test", "production"]),
  APP_NAME: z.string(),
  APP_PORT: z.coerce.number(),
  APP_URL: z.string().url(),
  API_PREFIX: z.string(),
  FRONTEND_URL: z.string().url(),
  ALLOWED_ORIGINS: z.string().optional(),
  // ------------------------ auth
  CONFIRM_TOKEN_SECRET: z.string(),
  CONFIRM_TOKEN_EXPIRES: z.coerce.number(),
  ACCESS_TOKEN_SECRET: z.string(),
  ACCESS_TOKEN_EXPIRES: z.coerce.number(),
  REFRESH_TOKEN_SECRET: z.string(),
  REFRESH_TOKEN_EXPIRES: z.coerce.number(),
  RESET_PASS_TOKEN_SECRET: z.string(),
  RESET_PASS_TOKEN_EXPIRES: z.coerce.number(),
  COOKIE_SECRET: z.string(),
  // oauth
  GOOGLE_CLIENT_ID: z.string(),
  GOOGLE_CLIENT_SECRET: z.string(),
  GOOGLE_CALLBACK_URL: z.string(),
  // ------------------------ db
  DB_TYPE: z.enum(["mysql", "mariadb", "postgres", "sqlite"]),
  DB_HOST: z.string(),
  DB_PORT: z.coerce.number(),
  DB_USER: z.string(),
  DB_PASSWORD: z.string(),
  DB_NAME: z.string(),
  DB_URL: z.string().url(),
  // ------------------------ email
  MAIL_HOST: z.string(),
  MAIL_PORT: z.coerce.number(),
  MAIL_USER: z.string(),
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
