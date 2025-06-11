import { registerAs } from "@nestjs/config";
import path from "node:path";

import { env } from "./env";

const basePath = process.cwd();

export const appConfig = registerAs("app", () => ({
  env: env.NODE_ENV,
  name: env.APP_NAME,
  port: env.APP_PORT,
  appUrl: env.APP_URL,
  frontendUrl: env.FRONTEND_URL,
  allowedOrigins: env.ALLOWED_ORIGINS ? env.ALLOWED_ORIGINS.split(",") : "*",
}));

export const dbConfig = registerAs("database", () => ({
  url: env.DB_URL,
  sql: {
    type: env.DB_TYPE,
    host: env.DB_HOST,
    port: env.DB_PORT,
    dbName: env.DB_NAME,
    username: env.DB_USER,
    password: env.DB_PASSWORD,
    synchronize: true,
    maxConnections: 100,
  },
  redis: {
    // url: env.REDIS_URI,
    // username: env.REDIS_USERNAME,
    // password: env.REDIS_PASSWORD,
    // host: env.REDIS_HOST,
    // port: env.REDIS_PORT,
    // ttl: env.REDIS_TTL,
  },
}));

export const authConfig = registerAs("auth", () => ({
  confirmTokenSecret: env.CONFIRM_TOKEN_SECRET,
  confirmTokenExpires: env.CONFIRM_TOKEN_EXPIRES,
  accessTokenSecret: env.ACCESS_TOKEN_SECRET,
  accessTokenExpires: env.ACCESS_TOKEN_EXPIRES,
  refreshTokenSecret: env.REFRESH_TOKEN_SECRET,
  refreshTokenExpires: env.REFRESH_TOKEN_EXPIRES,
  resetPasswordTokenSecret: env.RESET_PASS_TOKEN_SECRET,
  resetPasswordTokenExpires: env.RESET_PASS_TOKEN_EXPIRES,
  cookieSecret: env.COOKIE_SECRET,
  // oauth
  googleClientId: env.GOOGLE_CLIENT_ID,
  googleClientSecret: env.GOOGLE_CLIENT_SECRET,
  googleCallbackUrl: env.GOOGLE_CALLBACK_URL,
}));

export const mailConfig = registerAs("mail", () => ({
  // driver: env.MAIL_DRIVER,
  host: env.MAIL_HOST,
  port: env.MAIL_PORT,
  username: env.MAIL_USER,
  password: env.MAIL_PASSWORD,
  encryption: env.MAIL_ENCRYPTION,
  fromAddress: env.MAIL_FROM_ADDRESS,
  fromName: env.MAIL_FROM_NAME,
  supportAddress: env.SUPPORT_MAIL_ADDRESS,
}));

export const storageConfig = registerAs("storage", () => ({
  basePath,
  defaultDisk: env.FILESYSTEM_DISK,
  disk: {
    public: {
      dirver: "public",
      rootPath: path.join(basePath, "public"),
      // url: env.NEXT_PUBLIC_API_URL,
    },
    s3: {
      driver: "s3",
      keyId: env.AWS_ACCESS_KEY_ID,
      secret: env.AWS_SECRET_ACCESS_KEY,
      region: env.AWS_DEFAULT_REGION,
      bucket: env.AWS_BUCKET,
      url: env.AWS_URL,
    },
  },
}));
