import path from "path";

import { registerAs } from "@nestjs/config";

import { env } from "./env";

const basePath = process.cwd();

export const appConfig = registerAs("app", () => ({
  env: env.APP_ENV,
  port: env.APP_PORT,
  name: env.APP_NAME,
  apiUrl: env.APP_URL,
  clientUrl: env.CLIENT_URL,
  allowedOrigins: env.ALLOWED_ORIGINS ? env.ALLOWED_ORIGINS.split(",") : "*",
}));

export const authConfig = registerAs("auth", () => ({
  // email config
  resetPasswordTokenSecret: "secret=/-skajflkajflj=alfdjaljfal=kldfjalkjf/",
  resetPasswordTokenExpires: 5 * 60, // 5 minutes
  confirmTokenSecret: env.CONFIRMATION_TOKEN_SECRET,
  confirmTokenExpires: env.CONFIRMATION_TOKEN_EXPIRES,
  // auth
  cookieSecret: env.COOKIE_SECRET,
  bcryptSalt: env.BCRYPT_SALT,
  jwtAlgorithm: env.JWT_ALGORITHM,
  accessTokenSecret: env.JWT_ACCESS_TOKEN_SECRET,
  accessTokenExpires: env.JWT_ACCESS_TOKEN_EXPIRES,
  refreshTokenSecret: env.JWT_REFRESH_TOKEN_SECRET,
  refreshTokenExpires: env.JWT_REFRESH_TOKEN_EXPIRES,
  // oauth
  googleClientId: env.GOOGLE_CLIENT_ID,
  googleClientSecret: env.GOOGLE_CLIENT_SECRET,
  googleCallbackUrl: env.GOOGLE_CALLBACK_URL,
}));

export const dbConfig = registerAs("database", () => ({
  postgres: {
    host: env.DB_HOST,
    port: env.DB_PORT,
    name: env.DB_NAME,
    username: env.DB_USER,
    password: env.DB_PASSWORD,
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

export const mailConfig = registerAs("mail", () => ({
  // driver: env.MAIL_DRIVER,
  host: env.MAIL_HOST,
  port: env.MAIL_PORT,
  username: env.MAIL_USERNAME,
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
