import { Module } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";
import path from "node:path";

import { dbConfig } from "~/core/config/configs";

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      inject: [dbConfig.KEY],
      useFactory: async (config: Configs["db"]) => ({
        type: "postgres",
        host: config.postgres.host,
        port: config.postgres.port,
        username: config.postgres.username,
        password: config.postgres.password,
        database: config.postgres.name,
        synchronize: true,
        autoLoadEntities: true,
        entities: [path.join(__dirname, "..", "**", "*.entity{.ts,.js}")],
      }),
    }),
  ],
})
export class DatabaseModule {}
