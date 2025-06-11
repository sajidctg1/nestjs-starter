import { Module } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";
import path from "node:path";

import { dbConfig } from "~/configs";

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      inject: [dbConfig.KEY],
      useFactory: async (config: Configs["db"]) => ({
        type: config.sql.type,
        host: config.sql.host,
        port: config.sql.port,
        username: config.sql.username,
        password: config.sql.password,
        database: config.sql.dbName,
        synchronize: true,
        autoLoadEntities: true,
        entities: [path.join(__dirname, "..", "**", "*.entity{.ts,.js}")],
      }),
    }),
  ],
})
export class DatabaseModule {}
