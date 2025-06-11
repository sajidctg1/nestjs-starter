import { Module } from "@nestjs/common";
import { ConfigModule as NestConfigModule, ConfigType } from "@nestjs/config";

import {
  appConfig,
  authConfig,
  dbConfig,
  mailConfig,
  storageConfig,
} from "~/configs";

export interface IConfig {
  app: ConfigType<typeof appConfig>;
  auth: ConfigType<typeof authConfig>;
  db: ConfigType<typeof dbConfig>;
  storage: ConfigType<typeof storageConfig>;
  mail: ConfigType<typeof mailConfig>;
}

@Module({
  imports: [
    NestConfigModule.forRoot({
      load: [appConfig, authConfig, dbConfig, storageConfig, mailConfig],
      cache: true,
      isGlobal: true,
      expandVariables: true,
    }),
  ],
})
export class ConfigModule {}
